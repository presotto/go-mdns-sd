// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mdns

import (
	"flag"
	"log"
	"net"
	"reflect"
	"testing"
	"time"
)

var (
	// common options
	debugFlag = flag.Bool("debug", false, "turn on debugging")
)

type instance struct {
	host string
	port uint16
	txt  []string
}

func createInstance(service string, inst instance) *MDNS {
	s, err := NewMDNS(inst.host, "224.0.0.254:9999", "[FF02::FF]:9998", true, *debugFlag)
	if err != nil {
		log.Fatal("can't translate address: %v", err)
	}
	s.AddService(service, inst.host, inst.port, inst.txt...)
	return s
}

func checkDiscovered(t *testing.T, host string, discovered []ServiceInstance, instances []instance) {
	log.Printf("%s: instances %v %v", host, discovered, instances)
	if len(instances) != len(discovered) {
		t.Errorf("%s found %d instances expected %d", host, len(instances), len(discovered))
	}

	// Make sure the answers are what we were hoping for.
	var foundsrv int
	var foundtxt int
	for _, x := range discovered {
		for _, rr := range x.SrvRRs {
			for i, inst := range instances {
				if x.Name == inst.host && rr.Target == hostFQDN(inst.host) && rr.Port == inst.port {
					foundsrv = foundsrv | (1 << (uint8(i)))
				}
			}
		}
		for _, rr := range x.TxtRRs {
			for i, inst := range instances {
				if x.Name == inst.host && reflect.DeepEqual(rr.Txt, inst.txt) {
					foundtxt = foundtxt | (1 << (uint8(i)))
				}
			}
		}
	}
	for i, inst := range instances {
		if (foundsrv & (1 << (uint8(i)))) == 0 {
			t.Errorf("checkInstances %s didn't find SRV %s:%d", hostFQDN(inst.host), inst.port)
		}
		if (foundtxt & (1 << (uint8(i)))) == 0 {
			t.Errorf("checkInstances didn't find TXT %v", inst.txt)
		}
	}
}

func checkIps(t *testing.T, ips []net.IP) {
	log.Printf("%v", ips)
	if len(ips) == 0 {
		t.Errorf("no ips found")
	}
}

func watchFor(t *testing.T, c chan ServiceInstance, inst instance) {
	select {
	case x := <-c:
		for _, rr := range x.SrvRRs {
			log.Printf("watcher %s SRV %s %d", rr.Header().Name, rr.Target, rr.Port)
			if rr.Target == hostFQDN(inst.host) && rr.Port == inst.port {
				break
			}
			t.Errorf("watcher expected %s %d got %s %d", hostFQDN(inst.host), inst.port, rr.Target, rr.Port)
		}
		for _, rr := range x.TxtRRs {
			log.Printf("watcher %s TXT %v", rr.Header().Name, rr.Txt)
			if reflect.DeepEqual(rr.Txt, inst.txt) {
				break
			}
			t.Errorf("watcher expected %v got %v", inst.txt, rr.Txt)
		}
	case <-time.NewTimer(2 * time.Second).C:
		t.Errorf("watcher didn't hear %s %d", inst.host, inst.port)
	}
}

func TestMdns(t *testing.T) {
	instances := []instance{
		{"system1", 666, []string{""}},
		{"system2", 667, []string{"hoo haa", "haa hoo"}},
	}

	// Create two mdns instances.
	s1 := createInstance("veyronns", instances[0])
	c := s1.ServiceMemberWatch("veyronns")
	watchFor(t, c, instances[0])
	s2 := createInstance("veyronns", instances[1])

	// Multicast on each interface our desire to know about veyronns instances.
	s1.SubscribeToService("veyronns")
	s2.SubscribeToService("veyronns")

	// Wait for all messages to get out and get reflected back.
	time.Sleep(3 * time.Second)

	// Make sure service discovery returns both instances.
	discovered := s1.ServiceDiscovery("veyronns")
	checkDiscovered(t, instances[0].host, discovered, instances)
	discovered = s2.ServiceDiscovery("veyronns")
	checkDiscovered(t, instances[1].host, discovered, instances)

	// Look up addresses for both systems.
	ips, _ := s1.ResolveAddress(instances[1].host)
	checkIps(t, ips)
	ips, _ = s2.ResolveAddress(instances[0].host)
	checkIps(t, ips)

	// Make sure the watcher learned about both systems.
	watchFor(t, c, instances[1])
	close(c)

	s1.Stop()
	s2.Stop()
}
