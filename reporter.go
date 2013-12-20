package main

import (
	"encoding/csv"
	"io"
	"log"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/dustin/gomemcached"
)

type reportMsg struct {
	req      *gomemcached.MCRequest
	dnu      uint64
	from     string
	ts       time.Time
	isServer bool
	final    bool
}

func reportLatency(ch <-chan reportMsg, wg *sync.WaitGroup) {
	defer wg.Done()

	outf := io.Writer(os.Stdout)
	if *reportFile != "" {
		f, err := os.Create(*reportFile)
		if err != nil {
			log.Fatalf("Error creating report file:  %v", err)
		}
		defer f.Close()
		outf = f
	}

	cw := csv.NewWriter(outf)
	defer cw.Flush()

	cw.Write([]string{"ts", "from", "op",
		"reqklen", "reqbodylen",
		"resklen", "resbodylen",
		"duration"})

	type fkey struct {
		name   string
		opaque uint32
	}
	inflight := map[fkey]reportMsg{}

	below, above := 0, 0

	for msg := range ch {
		if msg.req == nil {
			continue
		}
		k := fkey{msg.from, msg.req.Opaque}
		if msg.isServer {
			req, exists := inflight[k]
			if exists {
				age := msg.ts.Sub(req.ts)
				if age > *threshold {
					above++
					cw.Write([]string{
						req.ts.Format(time.RFC3339),
						req.from, req.req.Opcode.String(),
						strconv.Itoa(len(req.req.Key)),
						strconv.Itoa(len(req.req.Body)),
						strconv.Itoa(len(msg.req.Key)),
						strconv.Itoa(len(msg.req.Body)),
						strconv.FormatInt(int64(age), 10),
					})
					if *verbose {
						log.Printf("%v came in %v ago", req.req, age)
					}
				} else {
					below++
				}
			}
			delete(inflight, k)
		} else {
			inflight[k] = msg
		}
	}

	log.Printf("Processed %v packets.  %v above, %v below. %v left in flight",
		above+below, above, below, len(inflight))
}
