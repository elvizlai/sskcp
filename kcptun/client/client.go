package client

import (
	"crypto/sha1"
	"io"
	"log"
	"math/rand"
	"net"
	"time"

	"github.com/elvizlai/sskcp/kcptun"

	"github.com/pkg/errors"
	kcp "github.com/xtaci/kcp-go"
	"github.com/xtaci/smux"
	"golang.org/x/crypto/pbkdf2"
)

func handleClient(sess *smux.Session, p1 io.ReadWriteCloser) {
	log.Println("stream opened")
	defer log.Println("stream closed")
	defer p1.Close()
	p2, err := sess.OpenStream()
	if err != nil {
		return
	}
	defer p2.Close()

	// start tunnel
	p1die := make(chan struct{})
	go func() {
		buf := kcptun.CopyBuf.Get().([]byte)
		io.CopyBuffer(p1, p2, buf)
		close(p1die)
		kcptun.CopyBuf.Put(buf)
	}()

	p2die := make(chan struct{})
	go func() {
		buf := kcptun.CopyBuf.Get().([]byte)
		io.CopyBuffer(p2, p1, buf)
		close(p2die)
		kcptun.CopyBuf.Put(buf)
	}()

	// wait for tunnel termination
	select {
	case <-p1die:
	case <-p2die:
	}
}

func RunClient(remoteAddr, localAddr string) {
	rand.Seed(int64(time.Now().Nanosecond()))

	addr, err := net.ResolveTCPAddr("tcp", localAddr)
	kcptun.CheckError(err)
	listener, err := net.ListenTCP("tcp", addr)
	kcptun.CheckError(err)

	pass := pbkdf2.Key([]byte(kcptun.Key), []byte(kcptun.SALT), 4096, 32, sha1.New)
	block, _ := kcp.NewAESBlockCrypt(pass)

	smuxConfig := smux.DefaultConfig()
	smuxConfig.MaxReceiveBuffer = kcptun.SockBuf
	smuxConfig.KeepAliveInterval = time.Duration(kcptun.KeepAlive) * time.Second

	createConn := func() (*smux.Session, error) {
		kcpconn, err := kcp.DialWithOptions(remoteAddr, block, kcptun.DataShard, kcptun.ParityShard)
		if err != nil {
			return nil, errors.Wrap(err, "createConn()")
		}
		kcpconn.SetStreamMode(true)
		kcpconn.SetNoDelay(kcptun.NoDelay, kcptun.Interval, kcptun.Resend, kcptun.NoCongestion)
		kcpconn.SetWindowSize(kcptun.SndWnd, kcptun.RcvWnd)
		kcpconn.SetMtu(kcptun.MTU)
		kcpconn.SetACKNoDelay(kcptun.AckNodelay)

		if err := kcpconn.SetDSCP(kcptun.DSCP); err != nil {
			log.Println("SetDSCP:", err)
		}

		if err := kcpconn.SetReadBuffer(kcptun.SockBuf); err != nil {
			log.Println("SetReadBuffer:", err)
		}
		if err := kcpconn.SetWriteBuffer(kcptun.SockBuf); err != nil {
			log.Println("SetWriteBuffer:", err)
		}

		// stream multiplex
		var session *smux.Session

		session, err = smux.Client(kcptun.NewCompStream(kcpconn), smuxConfig)

		if err != nil {
			return nil, errors.Wrap(err, "createConn()")
		}
		log.Println("connection:", kcpconn.LocalAddr(), "->", kcpconn.RemoteAddr())
		return session, nil
	}

	// wait until a connection is ready
	waitConn := func() *smux.Session {
		for {
			if session, err := createConn(); err == nil {
				return session
			}
			time.Sleep(time.Second)
		}
	}

	numconn := uint16(kcptun.Conn)
	muxes := make([]struct {
		session *smux.Session
		ttl     time.Time
	}, numconn)

	for k := range muxes {
		muxes[k].session = waitConn()
		muxes[k].ttl = time.Now().Add(time.Duration(kcptun.AutoExpire) * time.Second)
	}

	chScavenger := make(chan *smux.Session, 128)
	go scavenger(chScavenger, kcptun.ScavengeTTL)
	// go kcptun.SnmpLogger(kcptun.SnmpLog, kcptun.SnmpPeriod)
	rr := uint16(0)
	for {
		p1, err := listener.AcceptTCP()
		kcptun.CheckError(err)

		idx := rr % numconn

		// do auto expiration && reconnection
		if muxes[idx].session.IsClosed() || (kcptun.AutoExpire > 0 && time.Now().After(muxes[idx].ttl)) {
			chScavenger <- muxes[idx].session
			muxes[idx].session = waitConn()
			muxes[idx].ttl = time.Now().Add(time.Duration(kcptun.AutoExpire) * time.Second)
		}

		go handleClient(muxes[idx].session, p1)
		rr++
	}
}

type scavengeSession struct {
	session *smux.Session
	ts      time.Time
}

func scavenger(ch chan *smux.Session, ttl int) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var sessionList []scavengeSession
	for {
		select {
		case sess := <-ch:
			sessionList = append(sessionList, scavengeSession{sess, time.Now()})
			log.Println("session marked as expired")
		case <-ticker.C:
			var newList []scavengeSession
			for k := range sessionList {
				s := sessionList[k]
				if s.session.NumStreams() == 0 || s.session.IsClosed() {
					log.Println("session normally closed")
					s.session.Close()
				} else if ttl >= 0 && time.Since(s.ts) >= time.Duration(ttl)*time.Second {
					log.Println("session reached scavenge ttl")
					s.session.Close()
				} else {
					newList = append(newList, sessionList[k])
				}
			}
			sessionList = newList
		}
	}
}
