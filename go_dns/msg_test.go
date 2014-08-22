// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"encoding/hex"
	"reflect"
	"testing"
)

func TestDNSTxt(t *testing.T) {
	// Encode and decode a TXT rr.
	texts := []string{"the rain in spain", "falls mainly on the plane"}
	rr := &RR_TXT{RR_Header{"x.local.", TypeTXT, ClassINET | 0x8000, 10000, 0}, texts}
	buf := make([]byte, 512)
	off, ok := packRR(rr, buf, 0)
	if !ok {
		t.Errorf("packing txt rr failed")
	}
	rr_out, off_out, ok := unpackRR(buf, 0)
	if !ok {
		t.Error("unpacking txt rr failed")
	}
	if off != off_out {
		t.Error("unpacked txt len got %d, expected %d", off_out, off)
	}
	x, ok := rr_out.(*RR_TXT)
	if !ok {
		t.Errorf("rr type = %T; want *RR_TXT", rr)
	}
	if !reflect.DeepEqual(rr.Txt, x.Txt) {
		t.Errorf("txt rr expected %v, got %v", rr.Txt, x.Txt)
	}
}

func TestDNSParseSRVReply(t *testing.T) {
	data, err := hex.DecodeString(dnsSRVReply)
	if err != nil {
		t.Fatal(err)
	}
	msg := new(Msg)
	ok := msg.Unpack(data)
	if !ok {
		t.Fatalf("unpacking packet failed")
	}
	msg.String() // exercise this code path
	if g, e := len(msg.Answer), 5; g != e {
		t.Errorf("len(msg.Answer) = %d; want %d", g, e)
	}
	for idx, rr := range msg.Answer {
		if g, e := rr.Header().Rrtype, uint16(TypeSRV); g != e {
			t.Errorf("rr[%d].Header().Rrtype = %d; want %d", idx, g, e)
		}
		if _, ok := rr.(*RR_SRV); !ok {
			t.Errorf("answer[%d] = %T; want *RR_SRV", idx, rr)
		}
	}
	_, addrs, err := Answer("_xmpp-server._tcp.google.com.", uint16(TypeSRV), msg, "foo:53")
	if err != nil {
		t.Fatalf("answer: %v", err)
	}
	if g, e := len(addrs), 5; g != e {
		t.Errorf("len(addrs) = %d; want %d", g, e)
		t.Logf("addrs = %#v", addrs)
	}
	// repack and unpack.
	data2, ok := msg.Pack()
	msg2 := new(Msg)
	msg2.Unpack(data2)
	switch {
	case !ok:
		t.Errorf("failed to repack message")
	case !reflect.DeepEqual(msg, msg2):
		t.Errorf("repacked message differs from original")
	}
}

func TestDNSParseCorruptSRVReply(t *testing.T) {
	data, err := hex.DecodeString(dnsSRVCorruptReply)
	if err != nil {
		t.Fatal(err)
	}
	msg := new(Msg)
	ok := msg.Unpack(data)
	if !ok {
		t.Fatalf("unpacking packet failed")
	}
	msg.String() // exercise this code path
	if g, e := len(msg.Answer), 5; g != e {
		t.Errorf("len(msg.Answer) = %d; want %d", g, e)
	}
	for idx, rr := range msg.Answer {
		if g, e := rr.Header().Rrtype, uint16(TypeSRV); g != e {
			t.Errorf("rr[%d].Header().Rrtype = %d; want %d", idx, g, e)
		}
		if idx == 4 {
			if _, ok := rr.(*RR_Header); !ok {
				t.Errorf("answer[%d] = %T; want *RR_Header", idx, rr)
			}
		} else {
			if _, ok := rr.(*RR_SRV); !ok {
				t.Errorf("answer[%d] = %T; want *RR_SRV", idx, rr)
			}
		}
	}
	_, addrs, err := Answer("_xmpp-server._tcp.google.com.", uint16(TypeSRV), msg, "foo:53")
	if err != nil {
		t.Fatalf("answer: %v", err)
	}
	if g, e := len(addrs), 4; g != e {
		t.Errorf("len(addrs) = %d; want %d", g, e)
		t.Logf("addrs = %#v", addrs)
	}
}

// Valid DNS SRV reply
const dnsSRVReply = "0901818000010005000000000c5f786d70702d736572766572045f74637006676f6f67" +
	"6c6503636f6d0000210001c00c002100010000012c00210014000014950c786d70702d" +
	"73657276657234016c06676f6f676c6503636f6d00c00c002100010000012c00210014" +
	"000014950c786d70702d73657276657232016c06676f6f676c6503636f6d00c00c0021" +
	"00010000012c00210014000014950c786d70702d73657276657233016c06676f6f676c" +
	"6503636f6d00c00c002100010000012c00200005000014950b786d70702d7365727665" +
	"72016c06676f6f676c6503636f6d00c00c002100010000012c00210014000014950c78" +
	"6d70702d73657276657231016c06676f6f676c6503636f6d00"

// Corrupt DNS SRV reply, with its final RR having a bogus length
// (perhaps it was truncated, or it's malicious) The mutation is the
// capital "FF" below, instead of the proper "21".
const dnsSRVCorruptReply = "0901818000010005000000000c5f786d70702d736572766572045f74637006676f6f67" +
	"6c6503636f6d0000210001c00c002100010000012c00210014000014950c786d70702d" +
	"73657276657234016c06676f6f676c6503636f6d00c00c002100010000012c00210014" +
	"000014950c786d70702d73657276657232016c06676f6f676c6503636f6d00c00c0021" +
	"00010000012c00210014000014950c786d70702d73657276657233016c06676f6f676c" +
	"6503636f6d00c00c002100010000012c00200005000014950b786d70702d7365727665" +
	"72016c06676f6f676c6503636f6d00c00c002100010000012c00FF0014000014950c78" +
	"6d70702d73657276657231016c06676f6f676c6503636f6d00"
