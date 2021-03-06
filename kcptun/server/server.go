package server

import (
	"crypto/sha1"
	"io"
	"log"
	"math/rand"
	"net"
	"time"

	c "github.com/elvizlai/sskcp/config"
	"github.com/elvizlai/sskcp/kcptun"
	kcp "github.com/xtaci/kcp-go"
	"github.com/xtaci/smux"
	"golang.org/x/crypto/pbkdf2"
)

// handle multiplex-ed connection
func handleMux(conn io.ReadWriteCloser, target string) {
	// stream multiplex
	smuxConfig := smux.DefaultConfig()
	smuxConfig.MaxReceiveBuffer = c.SockBuf
	smuxConfig.KeepAliveInterval = time.Duration(c.KeepAlive) * time.Second

	mux, err := smux.Server(conn, smuxConfig)
	if err != nil {
		log.Println(err)
		return
	}
	defer mux.Close()
	for {
		p1, err := mux.AcceptStream()
		if err != nil {
			log.Println(err)
			return
		}
		p2, err := net.DialTimeout("tcp", target, 5*time.Second)
		if err != nil {
			p1.Close()
			log.Println(err)
			continue
		}
		go handleClient(p1, p2)
	}
}

func handleClient(p1, p2 io.ReadWriteCloser) {
	log.Println("stream opened")
	defer log.Println("stream closed")
	defer p1.Close()
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

func RunKCPTun(listenAddr, targetAddr string) {
	rand.Seed(int64(time.Now().Nanosecond()))

	pass := pbkdf2.Key([]byte(c.Key), []byte(c.SALT), 4096, 32, sha1.New)

	block, _ := kcp.NewAESBlockCrypt(pass)

	lis, err := kcp.ListenWithOptions(listenAddr, block, c.DataShard, c.ParityShard)
	kcptun.CheckError(err)
	log.Println("kcptun server using smux listening on:", listenAddr)

	if err := lis.SetDSCP(c.DSCP); err != nil {
		log.Println("SetDSCP:", err)
	}

	if err := lis.SetReadBuffer(c.SockBuf); err != nil {
		log.Println("SetReadBuffer:", err)
	}
	if err := lis.SetWriteBuffer(c.SockBuf); err != nil {
		log.Println("SetWriteBuffer:", err)
	}

	// go kcptun.SnmpLogger(kcptun.SnmpLog, kcptun.SnmpPeriod)

	for {
		if conn, err := lis.AcceptKCP(); err == nil {
			log.Println("remote address:", conn.RemoteAddr())
			conn.SetStreamMode(true)
			conn.SetWriteDelay(true)
			conn.SetNoDelay(c.NoDelay, c.Interval, c.Resend, c.NoCongestion)
			conn.SetWindowSize(c.SndWnd, c.RcvWnd)
			conn.SetMtu(c.MTU)
			conn.SetACKNoDelay(c.AckNodelay)
			conn.SetDSCP(c.DSCP)
			go handleMux(kcptun.NewCompStream(conn), targetAddr)
		} else {
			log.Printf("%+v", err)
		}
	}
}
