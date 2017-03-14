package config

var SndWnd = 1024 // set send window size(num of packets)
var RcvWnd = 1024 // set receive window size(num of packets)

var DSCP = 46 // set DSCP(6bit), using EF
var Conn = 1

var SnmpLog = "log"
var SnmpPeriod = 60

const (
	SALT       = "kcp-go" // SALT is use for pbkdf2 key expansion
	Key        = "1024"   // pre-shared secret between client and server
	AutoExpire = 0        // set auto expiration time(in seconds) for a single UDP connection, 0 to disable
	SockBuf    = 4194304  // socket buffer size in bytes
	KeepAlive  = 10

	DataShard   = 10 // set reed-solomon erasure coding - datashard
	ParityShard = 3  // set reed-solomon erasure coding - parityshard

	// fast3
	NoDelay      = 10
	Interval     = 20
	Resend       = 2
	NoCongestion = 1

	MTU         = 1350 // set maximum transmission unit for UDP packets
	AckNodelay  = true // flush ack immediately when a packet is received
	ScavengeTTL = 600  // set how long an expired connection can live(in sec), -1 to disable
)
