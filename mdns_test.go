// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mdns

import (
	"errors"
	"flag"
	"fmt"
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

func checkDiscovered(host string, discovered []ServiceInstance, instances ...instance) error {
	log.Printf("%s: instances %v %v", host, discovered, instances)
	if len(instances) != len(discovered) {
		return fmt.Errorf("%s found %d instances, but expected %d", host, len(instances), len(discovered))
	}

	// Make sure the answers are what we were hoping for.
	foundsrv := make(map[int]bool)
	foundtxt := make(map[int]bool)
	for _, x := range discovered {
		if len(x.SrvRRs) == 0 && len(x.TxtRRs) == 0 {
			for i, inst := range instances {
				if x.Name == inst.host && inst.port == 0 && len(inst.txt) == 0 {
					foundsrv[i] = true
					foundtxt[i] = true
				}
			}
			continue
		}

		for _, rr := range x.SrvRRs {
			found := false
			for i, inst := range instances {
				if x.Name == inst.host && rr.Target == hostFQDN(inst.host) && rr.Port == inst.port {
					found = true
					foundsrv[i] = true
				}
			}
			if !found {
				return fmt.Errorf("%s found unexpected SRV %s:%d", host, rr.Target, rr.Port)
			}
		}
		for _, rr := range x.TxtRRs {
			found := false
			for i, inst := range instances {
				if x.Name == inst.host && reflect.DeepEqual(rr.Txt, inst.txt) {
					found = true
					foundtxt[i] = true
				}
			}
			if !found {
				return fmt.Errorf("%s found unexpected TXT %v", host, rr.Txt)
			}
		}
	}
	for i, inst := range instances {
		if !foundsrv[i] {
			return fmt.Errorf("%s didn't find SRV %s:%d", host, hostFQDN(inst.host), inst.port)
		}
		if !foundtxt[i] {
			return fmt.Errorf("%s didn't find TXT %s:%d", host, inst.txt)
		}
	}
	return nil
}

func checkIps(ips []net.IP) error {
	log.Printf("%v", ips)
	if len(ips) == 0 {
		return errors.New("no ips found")
	}
	return nil
}

func watchFor(host string, c <-chan ServiceInstance, wants ...instance) error {
	discovered := make([]ServiceInstance, 0, len(wants))
loop:
	for len(discovered) < len(wants) {
		select {
		case inst := <-c:
			discovered = append(discovered, inst)
		case <-time.After(5 * time.Second):
			break loop
		}
	}
	return checkDiscovered(host+" watcher", discovered, wants...)
}

func watchForRemoved(host string, c <-chan ServiceInstance, wants ...instance) error {
	removed := make([]instance, len(wants))
	for i, want := range wants {
		removed[i] = instance{host: want.host}
	}
	return watchFor(host, c, removed...)
}

func TestMdns(t *testing.T) {
	instances := []instance{
		{"system1", 666, []string{""}},
		{"system2", 667, []string{"hoo haa", "haa hoo"}},
	}

	// Create two mdns instances.
	s1 := createInstance("veyronns", instances[0])
	w1, _ := s1.ServiceMemberWatch("veyronns")
	if err := watchFor(instances[0].host, w1, instances[0]); err != nil {
		t.Error(err)
	}
	s2 := createInstance("veyronns", instances[1])

	// Multicast on each interface our desire to know about veyronns instances.
	s1.SubscribeToService("veyronns")
	s2.SubscribeToService("veyronns")

	// Wait for all messages to get out and get reflected back.
	time.Sleep(3 * time.Second)

	// Make sure service discovery returns both instances.
	discovered := s1.ServiceDiscovery("veyronns")
	if err := checkDiscovered(instances[0].host, discovered, instances...); err != nil {
		t.Error(err)
	}
	discovered = s2.ServiceDiscovery("veyronns")
	if err := checkDiscovered(instances[1].host, discovered, instances...); err != nil {
		t.Error(err)
	}

	// Look up addresses for both systems.
	ips, _ := s1.ResolveAddress(instances[1].host)
	if err := checkIps(ips); err != nil {
		t.Error(err)
	}
	ips, _ = s2.ResolveAddress(instances[0].host)
	if err := checkIps(ips); err != nil {
		t.Error(err)
	}
	ips, _ = s2.ResolveAddress(instances[0].host)
	if err := checkIps(ips); err != nil {
		t.Error(err)
	}

	// Make sure the watcher learned about both systems.
	if err := watchFor(instances[0].host, w1, instances[1]); err != nil {
		t.Error(err)
	}

	// Make sure multiple watchers for the same service work as well.
	w2, stopw2 := s1.ServiceMemberWatch("veyronns")
	if err := watchFor(instances[0].host, w2, instances...); err != nil {
		t.Error(err)
	}
	// Make sure the watcher closed the channel when stopped.
	stopw2()
	if _, ok := <-w2; ok {
		t.Errorf("watcher didn't close the channel")
	}

	// Remove a service from one of the mdns instances.
	s1.RemoveService("veyronns", instances[0].host, instances[0].port, instances[0].txt...)

	// Wait for a goodbye message to get out and get reflected back.
	time.Sleep(3 * time.Second)

	// Make sure watcher learns the removed service.
	if err := watchForRemoved(instances[0].host, w1, instances[0]); err != nil {
		t.Error(err)
	}

	// Make sure service discovery doesn't return the removed service.
	discovered = s1.ServiceDiscovery("veyronns")
	if err := checkDiscovered(instances[0].host, discovered, instances[1]); err != nil {
		t.Error(err)
	}
	discovered = s2.ServiceDiscovery("veyronns")
	if err := checkDiscovered(instances[1].host, discovered, instances[1]); err != nil {
		t.Error(err)
	}

	s1.Stop()
	s2.Stop()
}
