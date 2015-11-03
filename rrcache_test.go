// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mdns

import (
	"testing"
	"time"

	"github.com/presotto/go-mdns-sd/go_dns"
)

var (
	short []dns.RR = []dns.RR{
		&dns.RR_TXT{dns.RR_Header{"x.local.", dns.TypeTXT, dns.ClassINET, 2, 0}, []string{"the rain in spain"}},
		&dns.RR_PTR{dns.RR_Header{"x.local.", dns.TypePTR, dns.ClassINET, 2, 0}, "y.local."},
	}
	long []dns.RR = []dns.RR{
		&dns.RR_TXT{dns.RR_Header{"x.local.", dns.TypeTXT, dns.ClassINET, 10000, 0}, []string{"falls mainly on the plain"}},
		&dns.RR_PTR{dns.RR_Header{"x.local.", dns.TypePTR, dns.ClassINET, 10000, 0}, "z.local."},
	}
	override []dns.RR = []dns.RR{
		&dns.RR_TXT{dns.RR_Header{"x.local.", dns.TypeTXT, dns.ClassINET | 0x8000, 10000, 0}, []string{"except on tuesday"}},
		&dns.RR_PTR{dns.RR_Header{"x.local.", dns.TypePTR, dns.ClassINET | 0x8000, 10000, 0}, "q.local."},
	}
	goodbye []dns.RR = []dns.RR{
		&dns.RR_TXT{dns.RR_Header{"x.local.", dns.TypeTXT, dns.ClassINET, 0, 0}, []string{"except on tuesday"}},
		&dns.RR_PTR{dns.RR_Header{"x.local.", dns.TypePTR, dns.ClassINET, 0, 0}, "q.local."},
	}
)

// Lookup RRs that match.
func lookup(cache *rrCache, dn string, rrtype uint16) []dns.RR {
	rc := make(chan dns.RR, 10)
	go func() {
		cache.Lookup(dn, rrtype, rc)
		close(rc)
	}()
	rrs := make([]dns.RR, 0)
	for rr := <-rc; rr != nil; rr = <-rc {
		rrs = append(rrs, rr)
	}
	return rrs
}

// Compare two lists of RRs.
func compare(a, b []dns.RR) bool {
	if len(a) != len(b) {
		return false
	}
	for _, rrb := range b {
		found := false
	L:
		for _, rra := range a {
			if rra.Header().Rrtype != rrb.Header().Rrtype {
				continue
			}
			if rra.Header().Ttl != rrb.Header().Ttl {
				continue
			}
			switch rra := rra.(type) {
			case *dns.RR_TXT:
				rrb := rrb.(*dns.RR_TXT)
				if rra.Txt[0] == rrb.Txt[0] {
					found = true
					break L
				}
			case *dns.RR_PTR:
				rrb := rrb.(*dns.RR_PTR)
				if rra.Ptr == rrb.Ptr {
					found = true
					break L
				}
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func TestRRCache(t *testing.T) {
	cache := newRRCache(*logLevelFlag)
	// Cache a number of RRs with short TTLs.
	for _, rr := range short {
		cache.Add(rr)
	}

	// Cache a number of RRs with long TTLs.
	for _, rr := range long {
		cache.Add(rr)
	}

	// Make sure all the RRs are still there.
	x := lookup(cache, "x.local.", dns.TypeALL)
	if !compare(x, append(short, long...)) {
		t.Errorf("%v != %v", x, append(short, long...))
	}

	// Lookup only RR_TXT entries
	x = lookup(cache, "x.local.", dns.TypeTXT)
	if !compare(x, []dns.RR{short[0], long[0]}) {
		t.Errorf("%v != %v", x, []dns.RR{short[0], long[0]})
	}

	// Wait past the short TTL and make sure only the long ones are still there.
	time.Sleep(5 * time.Second)
	x = lookup(cache, "x.local.", dns.TypeALL)
	if !compare(x, long) {
		t.Errorf("%v != %v", x, long)
	}

	// Make sure cache flush works.  The new entries should override rather than append.
	for _, rr := range override {
		cache.Add(rr)
	}
	x = lookup(cache, "x.local.", dns.TypeALL)
	if !compare(x, override) {
		t.Errorf("%v != %v", x, override)
	}

	// Make sure goodbye works.  The entries should be deleted after one second.
	for _, rr := range goodbye {
		cache.Add(rr)
	}
	time.Sleep(2 * time.Second)
	x = lookup(cache, "x.local.", dns.TypeALL)
	if len(x) != 0 {
		t.Errorf("%v != []", x)
	}
}
