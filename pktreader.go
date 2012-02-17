package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/dustin/gomemcached"
	"github.com/dustin/gomemcached/server"
	"github.com/dustin/gopcap"
)

var timeScale *float64 = flag.Float64("timescale", 1.0,
	"The device that speeds up and slows down time")

const channelSize = 10000

type bytesource struct {
	ch       <-chan []byte
	reporter chan<- gomemcached.CommandCode
	current  []byte
}

func (b *bytesource) Read(out []byte) (int, error) {
	if len(b.current) == 0 {
		var ok bool
		b.current, ok = <-b.ch
		if !ok {
			return 0, io.EOF
		}
	}
	copied := copy(out, b.current)
	b.current = b.current[copied:]
	return copied, nil
}

func NewByteSource(from <-chan []byte, rchan chan<- gomemcached.CommandCode) *bytesource {
	return &bytesource{ch: from, reporter: rchan}
}

func readUntil(r *bufio.Reader, b byte) error {
	one := []byte{0}
	for {
		bytes, err := r.Peek(1)
		if err != nil {
			return err
		}
		if len(bytes) == 1 && bytes[0] == b {
			return nil
		}
		n, err := r.Read(one)
		if err != nil {
			return err
		}
		if n == 1 && one[0] == b {
			return nil
		}
	}
	panic("Unreachable")
	return nil
}

func processRequest(name string, ch *bytesource, req *gomemcached.MCRequest) {
	// fmt.Printf("from %v: %v\n", name, pkt)
	ch.reporter <- req.Opcode
}

func consumer(name string, ch *bytesource) {
	msgs := 0
	rd := bufio.NewReader(ch)
	ever := true
	for ever {
		pkt, err := memcached.ReadPacket(rd)
		switch {
		case err == nil:
			switch pkt.Opcode {
			case gomemcached.GET, gomemcached.SET, gomemcached.GETQ,
				gomemcached.SETQ, gomemcached.DELETE:
				if len(pkt.Key) == 0 {
					fmt.Printf("Weird invalid looking packet: %v\n", pkt)
				} else {
					processRequest(name, ch, &pkt)
				}
			default:
				// not weird, invalid looking request
				processRequest(name, ch, &pkt)
			}
			msgs++
		default:
			// fmt.Printf("recovering from error:  %v\n", err)
			err = readUntil(rd, gomemcached.REQ_MAGIC)
			if err != nil {
				ever = false
				if err != io.EOF {
					fmt.Printf("Got an error seeking truth: %v", err)
				}
			}
		case err == io.EOF:
			ever = false
		}
	}
	dnu := uint64(0)
	// Just read the thing to completion.
	for bytes := range ch.ch {
		dnu += uint64(len(bytes))
	}
	fmt.Printf("Completed %d messages, did not understand %s from %s\n",
		msgs, humanize.Bytes(dnu), name)
}

func syncTime(pktTime, firstPacket, localStart time.Time) {
	now := time.Now()
	pktElapsed := pktTime.Sub(firstPacket)
	localElapsed := time.Duration(float64(now.Sub(localStart)) * *timeScale)

	toSleep := time.Duration(float64(pktElapsed-localElapsed) / *timeScale)
	if toSleep > 0 {
		time.Sleep(toSleep)
	}
}

func stream(filename string, rchan chan<- gomemcached.CommandCode) {
	h, err := pcap.Openoffline(filename)
	if h == nil {
		fmt.Printf("Openoffline(%s) failed: %s\n", filename, err)
		return
	}
	defer h.Close()

	clients := make(map[string]chan []byte)
	servers := make(map[string]bool)

	pkt := h.Next()
	if pkt == nil {
		fmt.Printf("No packets.")
		return
	}
	started := time.Now()
	first := pkt.Time.Time()

	for ; pkt != nil; pkt = h.Next() {
		pkt.Decode()
		tcp, ip := pkt.TCP, pkt.IP
		if tcp != nil {
			isAck := tcp.Flags&pcap.TCP_ACK != 0
			sender := fmt.Sprintf("%s:%d", ip.SrcAddr(), tcp.SrcPort)
			isServer := servers[sender]
			if tcp.Flags&pcap.TCP_SYN != 0 && isAck {
				servers[sender] = true
				isServer = true
			}

			if !isServer {
				ch := clients[sender]
				if ch == nil {
					ch = make(chan []byte, channelSize)
					go consumer(sender, NewByteSource(ch, rchan))
					clients[sender] = ch
					// fmt.Printf("Inferred connect from " + sender + "\n")
				}
				if len(pkt.Payload) > 0 {
					ch <- pkt.Payload
				}
				if tcp.Flags&(pcap.TCP_SYN|pcap.TCP_RST) != 0 && !isAck {
					close(clients[sender])
					delete(clients, sender)
					// fmt.Printf("Disconnect from " + sender + "\n")
				}
			}
		}
		t := pkt.Time.Time()
		syncTime(t, first, started)
	}
	for _, ch := range clients {
		close(ch)
	}
}

func report(ch <-chan gomemcached.CommandCode, wg *sync.WaitGroup) {
	counts := [256]uint64{}
	for cc := range ch {
		counts[int(cc)]++
	}

	tw := tabwriter.NewWriter(os.Stdout, 8, 4, 2, ' ', 0)
	for id, count := range counts {
		if count > 0 {
			cmd := gomemcached.CommandCode(id).String()
			fmt.Fprintf(tw, "%s\t%d\n", cmd, count)
		}
	}
	tw.Flush()

	wg.Done()
}

func main() {
	flag.Parse()
	reportchan := make(chan gomemcached.CommandCode, 100000)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go report(reportchan, &wg)
	stream(flag.Arg(0), reportchan)
	close(reportchan)
	wg.Wait()
}
