package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/elvizlai/sskcp/kcptun"
	kcps "github.com/elvizlai/sskcp/kcptun/server"
	ss "github.com/elvizlai/sskcp/shadowsocks"
)

func main() {
	log.SetOutput(os.Stdout)

	var ssConfig ss.Config
	var printVer bool
	var core int

	flag.BoolVar(&printVer, "version", false, "print version")
	flag.StringVar(&configFile, "c", "config.json", "specify config file")
	flag.StringVar(&ssConfig.Password, "k", "", "password")
	flag.IntVar(&ssConfig.ServerPort, "p", 0, "server port")
	flag.IntVar(&ssConfig.Timeout, "t", 300, "timeout in seconds")
	flag.StringVar(&ssConfig.Method, "m", "", "encryption method, default: aes-256-cfb")
	flag.IntVar(&core, "core", 0, "maximum number of CPU cores to use, default is determinied by Go runtime")
	flag.BoolVar((*bool)(&debug), "d", false, "print debug message")
	flag.BoolVar(&udp, "u", false, "UDP Relay")

	flag.IntVar(&kcptun.SndWnd, "snd", 1024, "set send window size(num of packets)")
	flag.IntVar(&kcptun.RcvWnd, "rcv", 1024, "set receive window size(num of packets)")
	flag.IntVar(&kcptun.DSCP, "dscp", 46, "set DSCP(6bit)")

	flag.Parse()

	if printVer {
		ss.PrintVersion()
		os.Exit(0)
	}

	ss.SetDebug(debug)

	if strings.HasSuffix(ssConfig.Method, "-auth") {
		ssConfig.Method = ssConfig.Method[:len(ssConfig.Method)-5]
		ssConfig.Auth = true
	}

	var err error
	config, err = ss.ParseConfig(configFile)
	if err != nil {
		if !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "error reading %s: %v\n", configFile, err)
			os.Exit(1)
		}
		config = &ssConfig
		ss.UpdateConfig(config, config)
	} else {
		ss.UpdateConfig(config, &ssConfig)
	}
	if config.Method == "" {
		config.Method = "aes-256-cfb"
	}
	if err = ss.CheckCipherMethod(config.Method); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err = unifyPortPassword(config); err != nil {
		os.Exit(1)
	}
	if core > 0 {
		runtime.GOMAXPROCS(core)
	}
	for port, password := range config.PortPassword {
		go run(port, password, config.Auth)
		if udp {
			go runUDP(port, password, config.Auth)
		}
		portNumeric, _ := strconv.Atoi(port)
		go kcps.RunKCPTun("0.0.0.0:"+strconv.Itoa(portNumeric+10000), "127.0.0.1:"+port)
	}

	waitSignal()
}
