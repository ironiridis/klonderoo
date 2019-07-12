package chromecast

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/ironiridis/klonderoo/mdns"
)

/*
func ListenAndLog() {
	a, err := net.ResolveUDPAddr("udp4", "224.0.0.251:5353")
	errassert.Verbose("resolve UDP address", err)
	l, err := net.ListenMulticastUDP("udp", nil, a)
	errassert.Verbose("listening for multicast", err)
	l.SetReadBuffer(9200) // largest jumbo frame packet

	buf := make([]byte, 9200)
	for {
		count, src, err := l.ReadFromUDP(buf)
		if err != nil {
			fmt.Printf("udp read: %v\n", err)
			continue
		}

		fmt.Printf("from %s (%d bytes): %02x\n", src, count, buf[:count])
	}
}
*/

// A Discoverer provides a channel which clients should range on for updates.
type Discoverer struct {
	mu            sync.RWMutex
	Chan          chan *DiscoveryUpdate
	stop          chan bool
	devs          knownDevices
	queryinterval time.Duration
	expireRate    int
}

// DeviceID is an opaque container for a Chromecast UUID.
type DeviceID [16]byte

// KnownDevice describes a Chromecast that has been discovered and seen recently.
type KnownDevice struct {
	ID           DeviceID
	FriendlyName string
	Hostname     string
	IPv4         string
	IPv6         string
	Model        string
}
type knownDevice struct {
	mu       sync.RWMutex
	lastSeen time.Time
	KnownDevice
}
type knownDevices map[DeviceID]*knownDevice

func (k *knownDevice) export() *KnownDevice {
	k.mu.RLock()
	c := k.KnownDevice
	k.mu.RUnlock()
	return &c
}

func (k *knownDevice) touch() {
	k.mu.Lock()
	k.lastSeen = time.Now()
	k.mu.Unlock()
}

// DiscoveryUpdate informs a goroutine reading a Discover channel when a Chromecast
// is newly discovered, or when a known Chromecast becomes unreachable. The receiving
// goroutine should assume that the Chromecast identified by ID has changed state in
// some way; coming, going, or updating.
type DiscoveryUpdate struct {
	ID     DeviceID
	Active bool
}

// Stop will cause the Discoverer to terminate its network activity and close Chan.
func (d *Discoverer) Stop() {
	close(d.stop)
	close(d.Chan)
}

// Get retrieves a copy of a device by its ID.
func (d *Discoverer) Get(id DeviceID) (*KnownDevice, error) {
	d.mu.RLock()
	m, ok := d.devs[id]
	d.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("no known device id of %032x", id)
	}
	return m.export(), nil
}

func (d *Discoverer) mdnsQuery() {
	for r := range mdns.QueryPTR("_googlecast._tcp.local.", false, 5*time.Second) {
		fmt.Printf("lol %+v\n", r)
	}
}

func (d *Discoverer) found(n *KnownDevice) {
	d.mu.RLock()
	k, ok := d.devs[n.ID]
	d.mu.RUnlock()
	if ok && *n == k.KnownDevice {
		// this device is already known, and this update
		// has only known values
		k.touch()
		return
	}

	d.mu.Lock()
	d.devs[n.ID] = &knownDevice{KnownDevice: *n, lastSeen: time.Now()}
	d.mu.Unlock()

	d.Chan <- &DiscoveryUpdate{ID: n.ID, Active: true}
}

func (d *Discoverer) expireCheck() {
	d.mu.RLock()
	n := time.Now()
	for id, k := range d.devs {
		k.mu.RLock()
		t := k.lastSeen
		k.mu.RUnlock()
		if n.Sub(t) > time.Duration(d.expireRate)*d.queryinterval {
			go d.forget(id)
		}
	}
	d.mu.RUnlock()
}

func (d *Discoverer) forget(id DeviceID) {
	d.mu.Lock()
	delete(d.devs, id)
	d.mu.Unlock()
	d.Chan <- &DiscoveryUpdate{ID: id, Active: false}
}

func (d *Discoverer) querier() {
	t := time.NewTimer(d.queryinterval)
	defer t.Stop()

	// run one mdns query immediately
	d.mdnsQuery()

	for {
		select {
		case <-d.stop:
			return
		case <-t.C:
			d.mdnsQuery()
			go d.expireCheck()
			t.Reset(d.queryinterval)
		}
	}
}

// SetQueryInterval changes the length of time between network queries for devices.
func (d *Discoverer) SetQueryInterval(i time.Duration) {
	d.mu.Lock()
	d.queryinterval = i
	d.mu.Unlock()
}

// SetExpireRate defines the length of time until a device is considered "gone" as a
// multiple of the query interval. This must be at least 1, and defaults to 3.
func (d *Discoverer) SetExpireRate(m int) error {
	if m < 1 {
		return fmt.Errorf("expire rate of %d missed queries is invalid", m)
	}
	d.mu.Lock()
	d.expireRate = m
	d.mu.Unlock()
	return nil
}

// Discover creates a Discoverer and begins listening on the interface specified by ifc
// (or some OS-dependent one, if nil). "network" must be one of "udp", "udp4", or "udp6".
func Discover(network string, ifc *net.Interface) (*Discoverer, error) {
	d := &Discoverer{
		Chan:          make(chan *DiscoveryUpdate),
		stop:          make(chan bool),
		devs:          knownDevices{},
		queryinterval: 20 * time.Second,
		expireRate:    3,
	}
	go d.querier()

	return d, nil
}
