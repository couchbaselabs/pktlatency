package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/dustin/gomemcached"
	"github.com/dustin/gopcap"
)

var packetRecovery = flag.Bool("recover", true,
	"Attempt to recover from corrupt memcached streams")
var maxBodyLen = flag.Uint("maxBodyLen", uint(gomemcached.MaxBodyLen),
	"Maximum body length of a valid packet")
var verbose = flag.Bool("v", false, "print out all the things")
var threshold = flag.Duration("thresh", time.Millisecond*3,
	"Threshold for reporting performance")
var reportFile = flag.String("report", "", "Path to csv report to produce")
var minKLen = flag.Int("minkey", 1, "minimum expected size of a key")
var maxKLen = flag.Int("maxkey", 64, "maximum expected size of a key")
var portNum = flag.Int("port", 11210, "mc binary port to identify")

const channelSize = 10000

var childrenWG = sync.WaitGroup{}

func stream(filename string, rchan chan<- reportMsg) {
	h, err := pcap.Openoffline(filename)
	if h == nil {
		log.Fatalf("Openoffline(%s) failed: %s", filename, err)
	}
	defer h.Close()

	clients := make(map[string]chan bsinput)
	servers := make(map[string]chan bsinput)

	defer func() {
		for _, ch := range clients {
			close(ch)
		}
		for _, ch := range servers {
			close(ch)
		}
	}()

	for pkt := h.Next(); pkt != nil; pkt = h.Next() {
		pkt.Decode()
		tcp, ip := pkt.TCP, pkt.IP
		if tcp != nil {
			isAck := tcp.Flags&pcap.TCP_ACK != 0
			sender := fmt.Sprintf("%s:%d", ip.SrcAddr(), tcp.SrcPort)
			_, isServer := servers[sender]
			if (tcp.Flags&pcap.TCP_SYN != 0 && isAck) ||
				tcp.SrcPort == uint16(*portNum) {
				isServer = true
			}

			if isServer {
				ch := servers[sender]
				if ch == nil {
					ch = make(chan bsinput, channelSize)
					childrenWG.Add(1)
					go serverconsumer(sender, NewByteSource(ch, rchan))
					servers[sender] = ch
				}
				if len(pkt.Payload) > 0 {
					ch <- bsinput{pkt.Time.Time(), pkt.Payload}
				}
				if tcp.Flags&(pcap.TCP_SYN|pcap.TCP_RST) != 0 && !isAck {
					close(servers[sender])
					delete(servers, sender)
					log.Printf("Disconnect from " + sender)
				}
			} else {
				name := fmt.Sprintf("%s:%d", ip.DestAddr(), tcp.DestPort)
				ch := clients[sender]
				if ch == nil {
					ch = make(chan bsinput, channelSize)
					childrenWG.Add(1)
					go clientconsumer(name, NewByteSource(ch, rchan))
					clients[sender] = ch
					log.Printf("Inferred connect from " + sender)
				}
				if len(pkt.Payload) > 0 {
					ch <- bsinput{pkt.Time.Time(), pkt.Payload}
				}
			}
		}
	}
}

func main() {
	log.SetFlags(log.Lmicroseconds)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [params] file.pcap\n",
			os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()
	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "ERROR:  Must supply a pcap file.\n")
		flag.Usage()
		os.Exit(1)
	}
	gomemcached.MaxBodyLen = int(*maxBodyLen)
	reportchan := make(chan reportMsg, 100000)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go reportLatency(reportchan, &wg)
	stream(flag.Arg(0), reportchan)
	childrenWG.Wait()
	close(reportchan)
	wg.Wait()
}
