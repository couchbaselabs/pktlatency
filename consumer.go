package main

import (
	"bufio"
	"io"
	"log"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/dustin/go-humanize"
	"github.com/dustin/gomemcached"
	"github.com/dustin/gomemcached/server"
)

type bsinput struct {
	t time.Time
	b []byte
}

type bytesource struct {
	ch       <-chan bsinput
	reporter chan<- reportMsg
	current  []byte
	ts       time.Time
}

func (b *bytesource) Read(out []byte) (int, error) {
	if len(b.current) == 0 {
		pkt, ok := <-b.ch
		if !ok {
			return 0, io.EOF
		}
		b.ts = pkt.t
		b.current = pkt.b
	}
	copied := copy(out, b.current)
	b.current = b.current[copied:]
	return copied, nil
}

func NewByteSource(from <-chan bsinput, rchan chan<- reportMsg) *bytesource {
	return &bytesource{ch: from, reporter: rchan}
}

func readUntil(r *bufio.Reader, b byte) (skipped uint64, err error) {
	one := []byte{0}
	for {
		var bytes []byte
		bytes, err := r.Peek(1)
		if err != nil {
			return skipped, err
		}
		if len(bytes) == 1 && bytes[0] == b {
			return skipped, nil
		}
		n, err := r.Read(one)
		if err != nil {
			return skipped, err
		}
		skipped += uint64(n)
		if n == 1 && one[0] == b {
			return skipped, nil
		}
	}
}

type validator func(*gomemcached.MCRequest) bool

func allArePrintable(s string) bool {
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

func saneKey(req *gomemcached.MCRequest) bool {
	return len(req.Key) >= *minKLen && len(req.Key) <= *maxKLen &&
		utf8.Valid(req.Key) &&
		allArePrintable(string(req.Key))
}
func noKey(req *gomemcached.MCRequest) bool   { return len(req.Key) == 0 }
func noBody(req *gomemcached.MCRequest) bool  { return len(req.Body) == 0 }
func hasBody(req *gomemcached.MCRequest) bool { return len(req.Body) > 0 }

var clientValidators = map[gomemcached.CommandCode][]validator{
	gomemcached.GET:    {saneKey, noBody},
	gomemcached.GETQ:   {saneKey, noBody},
	gomemcached.DELETE: {saneKey, noBody},
	gomemcached.SET:    {saneKey, hasBody},
	gomemcached.SETQ:   {saneKey, hasBody},
	gomemcached.ADD:    {saneKey, hasBody},
	gomemcached.ADDQ:   {saneKey, hasBody},
}

var serverValidators = map[gomemcached.CommandCode][]validator{
	gomemcached.GET:    {noKey, hasBody},
	gomemcached.GETQ:   {noKey, hasBody},
	gomemcached.DELETE: {noKey, noBody},
	gomemcached.SET:    {noKey, noBody},
	gomemcached.ADD:    {noKey, noBody},
}

func looksValid(req *gomemcached.MCRequest,
	validators map[gomemcached.CommandCode][]validator) bool {

	vs, ok := validators[req.Opcode]
	if !ok {
		return false
	}

	for _, v := range vs {
		if !v(req) {
			return false
		}
	}

	return true
}

func clientLooksValid(req *gomemcached.MCRequest) bool {
	return looksValid(req, clientValidators)
}

func serverLooksValid(req *gomemcached.MCRequest) bool {
	return looksValid(req, serverValidators)
}

func clientconsumer(name string, ch *bytesource) {
	defer childrenWG.Done()

	msgs := 0
	rd := bufio.NewReader(ch)
	dnu := uint64(0)
	ever := true
	for ever {
		pkt, err := memcached.ReadPacket(rd)
		switch {
		case err == nil:
			if clientLooksValid(&pkt) {
				ch.reporter <- reportMsg{req: &pkt, from: name, ts: ch.ts}
			} else {
				log.Printf("Invalid request found: op=%v, klen=%v, bodylen=%v",
					pkt.Opcode, len(pkt.Key), len(pkt.Body))
			}
			msgs++
		default:
			if *packetRecovery {
				skipped, err := readUntil(rd, gomemcached.REQ_MAGIC)
				dnu += skipped
				if err != nil {
					ever = false
					if err != io.EOF {
						log.Printf("Got an error seeking truth: %v", err)
					}
				}
			} else {
				ever = false
			}
		case err == io.EOF:
			ever = false
		}
	}
	// Just read the thing to completion.
	for bytes := range ch.ch {
		dnu += uint64(len(bytes.b))
	}
	if *verbose {
		log.Printf("Processed %d messages, skipped %s from %s",
			msgs, humanize.Bytes(dnu), name)
	}
	ch.reporter <- reportMsg{final: true, dnu: dnu}
}

func serverconsumer(name string, ch *bytesource) {
	defer childrenWG.Done()

	msgs := 0
	rd := bufio.NewReader(ch)
	dnu := uint64(0)
	ever := true
	for ever {
		pkt, err := memcached.ReadPacket(rd)
		switch {
		case err == nil:
			if serverLooksValid(&pkt) {
				ch.reporter <- reportMsg{req: &pkt, from: name, ts: ch.ts, isServer: true}
			} else {
				log.Printf("Invalid response found: op=%v, klen=%v, bodylen=%v",
					pkt.Opcode, len(pkt.Key), len(pkt.Body))
			}
			msgs++
		default:
			if *packetRecovery {
				skipped, err := readUntil(rd, gomemcached.RES_MAGIC)
				dnu += skipped
				if err != nil {
					ever = false
					if err != io.EOF {
						log.Printf("Got an error seeking truth: %v", err)
					}
				}
			} else {
				ever = false
			}
		case err == io.EOF:
			ever = false
		}
	}
	// Just read the thing to completion.
	for bytes := range ch.ch {
		dnu += uint64(len(bytes.b))
	}
	if *verbose {
		log.Printf("Processed %d messages, skipped %s from %s",
			msgs, humanize.Bytes(dnu), name)
	}
}
