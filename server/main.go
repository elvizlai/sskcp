package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"strconv"
	"strings"

	c "github.com/elvizlai/sskcp/config"
	kcps "github.com/elvizlai/sskcp/kcptun/server"
	ss "github.com/elvizlai/sskcp/shadowsocks"
	sss "github.com/elvizlai/sskcp/ss/server"
)

func main() {
	log.SetOutput(os.Stdout)

	var config *ss.Config
	var cmdConfig ss.Config
	var printVer bool
	var core int

	flag.BoolVar(&printVer, "version", false, "print version")
	flag.StringVar(&sss.ConfigFile, "c", "config.json", "specify ss config file")
	flag.StringVar(&cmdConfig.Password, "k", "", "password")
	flag.IntVar(&cmdConfig.ServerPort, "p", 0, "server port")
	flag.IntVar(&cmdConfig.Timeout, "t", 300, "timeout in seconds")
	flag.StringVar(&cmdConfig.Method, "m", "", "encryption method, default: aes-256-cfb")
	flag.IntVar(&core, "core", 0, "maximum number of CPU cores to use, default is determinied by Go runtime")
	flag.BoolVar((*bool)(&sss.Debug), "d", false, "print debug message")
	flag.BoolVar(&sss.UDP, "u", false, "UDP Relay")

	flag.IntVar(&c.SndWnd, "snd", 1024, "set send window size(num of packets)")
	flag.IntVar(&c.RcvWnd, "rcv", 1024, "set receive window size(num of packets)")
	flag.IntVar(&c.DSCP, "dscp", 46, "set DSCP(6bit)")

	flag.Parse()

	if printVer {
		ss.PrintVersion()
		os.Exit(0)
	}

	ss.SetDebug(sss.Debug)

	if strings.HasSuffix(cmdConfig.Method, "-auth") {
		cmdConfig.Method = cmdConfig.Method[:len(cmdConfig.Method)-5]
		cmdConfig.Auth = true
	}

	var err error
	config, err = ss.ParseConfig(sss.ConfigFile)
	if err != nil {
		if !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "error reading %s: %v\n", sss.ConfigFile, err)
			os.Exit(1)
		}
		config = &cmdConfig
		ss.UpdateConfig(config, config)
	} else {
		ss.UpdateConfig(config, &cmdConfig)
	}
	if config.Method == "" {
		config.Method = "aes-256-cfb"
	}
	if err = ss.CheckCipherMethod(config.Method); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err = sss.UnifyPortPassword(config); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if core > 0 {
		runtime.GOMAXPROCS(core)
	}
	for port, password := range config.PortPassword {
		portNumeric, err := strconv.Atoi(port)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		go sss.Run(port, password, config.Auth)
		if sss.UDP {
			go sss.RunUDP(port, password, config.Auth)
		}
		go kcps.RunKCPTun("0.0.0.0:"+strconv.Itoa(10000+portNumeric), "127.0.0.1:"+port)
	}

	sss.WaitSignal()
}
