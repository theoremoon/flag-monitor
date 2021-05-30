package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/theoremoon/flag-monitor/dump"
	"github.com/theoremoon/flag-monitor/session"
	"golang.org/x/xerrors"
)

func run() error {
	var iface string
	var port int
	var pcapFmt string
	var rotateIntervalStr string
	var flagPcapFmt string
	var sessionFlushIntervalStr string
	var patternStr string
	var rotateFunc string
	var flagRotateFunc string

	flag.Usage = func() {
		fmt.Printf("usage: %s\n\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.StringVar(&iface, "i", "", "network interface to capture the packet")
	flag.StringVar(&pcapFmt, "w", "", "filename to dump pcap. strftime format is allowed")
	flag.StringVar(&rotateIntervalStr, "d", "1h", "duration of rotating pcap file dump")
	flag.StringVar(&rotateFunc, "z", "", "post rotate command")
	flag.StringVar(&flagPcapFmt, "flag-w", "", "filename to dump flag-included pcap. strftime format is allowed")
	flag.StringVar(&sessionFlushIntervalStr, "flag-d", "5m", "interval of flushing session")
	flag.StringVar(&flagRotateFunc, "flag-z", "", "post rotate command for flag file")
	flag.StringVar(&patternStr, "flag", "", "regular expression")
	flag.IntVar(&port, "p", -1, "port number to be monitored by this tool")

	flag.Parse()
	if pcapFmt == "" || iface == "" || port == -1 {
		flag.Usage()
		return nil
	}

	rotateInterval, err := time.ParseDuration(rotateIntervalStr)
	if err != nil {
		flag.Usage()
		return xerrors.Errorf(": %w", err)
	}

	sessionFlushInterval, err := time.ParseDuration(sessionFlushIntervalStr)
	if err != nil {
		flag.Usage()
		return xerrors.Errorf(": %w", err)
	}

	pattern, err := regexp.Compile(patternStr)
	if err != nil {
		flag.Usage()
		return xerrors.Errorf(": %w", err)
	}

	// timeout should be considiered
	handle, err := pcap.OpenLive(iface, 1600, false, 1)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	if err := handle.SetBPFFilter(fmt.Sprintf("tcp and port %d", port)); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := source.Packets()

	// sessionをflushするときに呼んでflagが含まれていたらdumpする
	flushHandler := func(sess *session.Session) {
		// パターンを探す
		buf := bytes.NewBuffer(make([]byte, 0, 1024))
		for _, p := range sess.Packets {
			tcp := p.Layer(layers.LayerTypeTCP).(*layers.TCP)
			buf.Write(tcp.Payload)
		}
		if !pattern.Match(buf.Bytes()) {
			return
		}

		// dumpする
		dumper, _ := dump.NewDumper(flagPcapFmt, uint32(handle.SnapLen()), handle.LinkType())
		if flagRotateFunc != "" {
			dumper.SetCloseCallback(func(p string) {
				exec.Command(flagRotateFunc, p).Run()
			})
		}
		for _, p := range sess.Packets {
			dumper.Write(p.Metadata().CaptureInfo, p.Data())
		}
		dumper.Close()
	}

	dumper, err := dump.NewRotateDumper(pcapFmt, uint32(handle.SnapLen()), handle.LinkType(), rotateInterval)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	if rotateFunc != "" {
		dumper.SetCloseCallback(func(p string) {
			exec.Command(rotateFunc, p)
		})
	}

	ticker := time.NewTicker(sessionFlushInterval)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGKILL, os.Interrupt)

	pool := session.NewPool()
	for {
		select {
		case packet := <-packets:
			// TCPのパケットにだけ興味がある
			_, isTCP := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
			if !isTCP {
				break
			}

			// normal dump
			if err := dumper.Write(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
				return xerrors.Errorf(": %w", err)
			}

			// insert into pool
			pool.AddTCP(packet, time.Now())

		case <-ticker.C:
			// closeしたsessionをflushするとき
			// flushは勝手にロックをとってくれる
			pool.Flush(time.Now().Add(-sessionFlushInterval), flushHandler)

		case s := <-sig:
			log.Printf("got a signal: %v\nexiting...\n", s)
			// signalを受け取ったらflushしてから抜ける
			dumper.Close()
			pool.Flush(time.Now().Add(-sessionFlushInterval), flushHandler)
			return nil
		}
	}
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("%+v\n", err)
	}
}
