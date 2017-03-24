package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path"
	"strconv"
	"strings"

	c "github.com/elvizlai/sskcp/config"
	kcpc "github.com/elvizlai/sskcp/kcptun/client"
	ss "github.com/elvizlai/sskcp/shadowsocks"
	ssc "github.com/elvizlai/sskcp/ss/client"
)

func main() {
	log.SetOutput(os.Stdout)

	var configFile, cmdServer, cmdLocal string
	var cmdConfig ss.Config
	var printVer, kcpOff bool

	flag.BoolVar(&printVer, "version", false, "print version")
	flag.StringVar(&configFile, "c", "config.json", "specify config file")
	flag.StringVar(&cmdServer, "s", "", "server address")
	flag.StringVar(&cmdLocal, "b", "", "local address, listen only to this address if specified")
	flag.StringVar(&cmdConfig.Password, "k", "", "password")
	flag.IntVar(&cmdConfig.ServerPort, "p", 0, "server port")
	flag.IntVar(&cmdConfig.Timeout, "t", 300, "timeout in seconds")
	flag.IntVar(&cmdConfig.LocalPort, "l", 0, "local socks5 proxy port")
	flag.StringVar(&cmdConfig.Method, "m", "", "encryption method, default: aes-256-cfb")
	flag.BoolVar((*bool)(&ssc.Debug), "d", false, "print debug message")
	flag.BoolVar(&cmdConfig.Auth, "A", false, "one time auth")

	flag.IntVar(&c.SndWnd, "snd", 128, "set send window size(num of packets)")
	flag.IntVar(&c.RcvWnd, "rcv", 512, "set receive window size(num of packets)")
	flag.IntVar(&c.DSCP, "dscp", 46, "set DSCP(6bit)")
	flag.IntVar(&c.Conn, "conn", 1, "set num of UDP connections to server")

	flag.IntVar(&c.NoDelay, "nodelay", 0, "set mode param nodelay")
	flag.IntVar(&c.Interval, "interval", 30, "set mode param interval")
	flag.IntVar(&c.Resend, "resend", 2, "set mode param resend")
	flag.IntVar(&c.NoCongestion, "nc", 1, "set mode param nc")

	flag.Parse()

	if printVer {
		ss.PrintVersion()
		os.Exit(0)
	}

	cmdConfig.Server = cmdServer
	ss.SetDebug(ssc.Debug)

	if strings.HasSuffix(cmdConfig.Method, "-auth") {
		cmdConfig.Method = cmdConfig.Method[:len(cmdConfig.Method)-5]
		cmdConfig.Auth = true
	}

	exists, err := ss.IsFileExists(configFile)
	// If no config file in current directory, try search it in the binary directory
	// Note there's no portable way to detect the binary directory.
	binDir := path.Dir(os.Args[0])
	if (!exists || err != nil) && binDir != "" && binDir != "." {
		oldConfig := configFile
		configFile = path.Join(binDir, "config.json")
		log.Printf("%s not found, try config file %s\n", oldConfig, configFile)
	}

	config, err := ss.ParseConfig(configFile)
	if err != nil {
		config = &cmdConfig
		if !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "error reading %s: %v\n", configFile, err)
			os.Exit(1)
		}
	} else {
		ss.UpdateConfig(config, &cmdConfig)
	}
	if config.Method == "" {
		config.Method = "aes-256-cfb"
	}
	if len(config.ServerPassword) == 0 {
		if !ssc.EnoughOptions(config) {
			fmt.Fprintln(os.Stderr, "must specify server address, password and both server/local port")
			os.Exit(1)
		}
	} else {
		if config.Password != "" || config.ServerPort != 0 || config.GetServerArray() != nil {
			fmt.Fprintln(os.Stderr, "given server_password, ignore server, server_port and password option:", config)
		}
		if config.LocalPort == 0 {
			fmt.Fprintln(os.Stderr, "must specify local port")
			os.Exit(1)
		}
	}

	if !kcpOff {
		config.Server = "127.0.0.1"
		config.ServerPort = 10000 + config.ServerPort
		portStr := strconv.Itoa(config.ServerPort)
		go kcpc.RunClient(cmdServer+":"+portStr, fmt.Sprint(config.Server)+":"+portStr)
	}

	ssc.ParseServerConfig(config)

	ssc.Run(cmdLocal + ":" + strconv.Itoa(config.LocalPort))
}
