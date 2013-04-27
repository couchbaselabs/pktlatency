package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/dustin/go-humanize"
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

func has(haystack []int, needle int) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}

func reportLatency(ch <-chan reportMsg, wg *sync.WaitGroup) {
	defer wg.Done()

	var outf io.Writer
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

	cw.Write([]string{"ts", "from", "duration"})

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
						req.from,
						strconv.FormatInt(int64(age), 10),
					})
					log.Printf("%v came in %v ago", req.req, age)
				} else {
					below++
				}
			}
			delete(inflight, k)
		} else {
			inflight[k] = msg
		}
	}

	log.Printf("Processed %v packets.  %v above, %v below", above+below, above, below)
}

func report(ch <-chan reportMsg, wg *sync.WaitGroup) {
	counts := [256]uint64{}
	var dnu uint64
	vbuckets := map[string][]int{}
	for msg := range ch {
		if msg.req != nil {
			counts[int(msg.req.Opcode)]++
			vb := int(msg.req.VBucket)
			ops := msg.req.Opcode.String()
			if l, ok := vbuckets[ops]; ok {
				if !has(l, vb) {
					vbuckets[ops] = append(l, vb)
				}
			} else {
				vbuckets[ops] = []int{vb}
			}
		} else {
			dnu += msg.dnu
		}
	}

	tw := tabwriter.NewWriter(os.Stdout, 8, 4, 2, ' ', 0)
	for id, count := range counts {
		if count > 0 {
			cmd := gomemcached.CommandCode(id).String()
			fmt.Fprintf(tw, "%s\t%d\n", cmd, count)
		}
	}
	tw.Flush()

	if *dumpJson {
		log.Printf("Vbuckets in use:")
		err := json.NewEncoder(os.Stdout).Encode(vbuckets)
		if err != nil {
			log.Printf("Error in JSON encoding:  %v", err)
		}
	}

	log.Printf("Did not understand %s bytes", humanize.Bytes(dnu))

	wg.Done()
}
