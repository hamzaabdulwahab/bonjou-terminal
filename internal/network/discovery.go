package network

import (
	"encoding/json"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/hamzawahab/bonjou-terminal/internal/config"
	"github.com/hamzawahab/bonjou-terminal/internal/logger"
)

// Peer represents an active Bonjou device on the LAN.
type Peer struct {
	Username string
	IP       string
	Port     int
	LastSeen time.Time
	Secret   string
}

type announcement struct {
	Username  string `json:"username"`
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	Timestamp int64  `json:"ts"`
	Secret    string `json:"secret"`
}

// DiscoveryService handles LAN peer discovery over UDP broadcasts.
type DiscoveryService struct {
	cfg       *config.Config
	logger    *logger.Logger
	peers     map[string]*Peer
	mu        sync.RWMutex
	localMu   sync.RWMutex
	stop      chan struct{}
	stopOnce  sync.Once
	wait      sync.WaitGroup
	started   bool
	localUser string
	localIP   string
	localPort int
}

func (d *DiscoveryService) isStopping() bool {
	select {
	case <-d.stop:
		return true
	default:
		return false
	}
}

func NewDiscoveryService(cfg *config.Config, logger *logger.Logger) *DiscoveryService {
	return &DiscoveryService{
		cfg:    cfg,
		logger: logger,
		peers:  make(map[string]*Peer),
		stop:   make(chan struct{}),
	}
}

// Start launches announcer and listener goroutines.
func (d *DiscoveryService) Start(username, ip string, port int) error {
	if d.started {
		return nil
	}
	d.localMu.Lock()
	d.localUser = username
	d.localIP = ip
	d.localPort = port
	d.localMu.Unlock()
	d.wait.Add(2)
	go d.listenLoop()
	go d.announceLoop()
	d.started = true
	return nil
}

// Stop requests goroutines to wind down.
func (d *DiscoveryService) Stop() {
	if !d.started {
		return
	}
	d.stopOnce.Do(func() { close(d.stop) })
	d.wait.Wait()
	d.started = false
}

// UpdateLocalUser switches the announcer to a new username.
func (d *DiscoveryService) UpdateLocalUser(username string) {
	d.localMu.Lock()
	d.localUser = username
	d.localMu.Unlock()
}

// UpdateLocalEndpoint refreshes the local IP/port and resets peer cache for new networks.
func (d *DiscoveryService) UpdateLocalEndpoint(ip string, port int) {
	if ip == "" && port <= 0 {
		return
	}
	d.localMu.Lock()
	if ip != "" {
		d.localIP = ip
	}
	if port > 0 {
		d.localPort = port
	}
	d.localMu.Unlock()

	d.mu.Lock()
	d.peers = make(map[string]*Peer)
	d.mu.Unlock()

	go d.ForceAnnounce()
}

// ForceAnnounce immediately broadcasts the latest local identity.
func (d *DiscoveryService) ForceAnnounce() {
	if !d.started || d.isStopping() {
		return
	}
	payload, ok := d.prepareAnnouncement()
	if !ok {
		return
	}
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		d.logger.Error("force announce socket: %v", err)
		return
	}
	defer conn.Close()
	enableBroadcast(conn)
	_ = conn.SetWriteBuffer(1024)
	addrs := d.broadcastAddrs()
	d.writeAnnouncement(conn, payload, addrs)
}

// ListPeers returns peers observed within the freshness window.
func (d *DiscoveryService) ListPeers() []Peer {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []Peer
	expiry := time.Now().Add(-15 * time.Second)
	for key, peer := range d.peers {
		if peer.LastSeen.Before(expiry) {
			delete(d.peers, key)
			continue
		}
		clone := *peer
		clone.Secret = ""
		out = append(out, clone)
	}
	return out
}

// Resolve takes a username or IP string and returns the matching peer.
func (d *DiscoveryService) Resolve(target string) (*Peer, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	// direct IP match first
	if peer, ok := d.peers[target]; ok {
		clone := *peer
		return &clone, nil
	}
	for _, peer := range d.peers {
		if peer.Username == target {
			clone := *peer
			return &clone, nil
		}
	}
	return nil, errors.New("peer not found")
}

// SharedSecret retrieves the most recent secret advertised by a peer.
func (d *DiscoveryService) SharedSecret(username, ip string) (string, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if ip != "" {
		if peer, ok := d.peers[ip]; ok {
			if peer.Secret != "" {
				return peer.Secret, true
			}
		}
	}
	if username != "" {
		for _, peer := range d.peers {
			if peer.Username == username && peer.Secret != "" {
				return peer.Secret, true
			}
		}
	}
	return "", false
}

func (d *DiscoveryService) listenLoop() {
	defer d.wait.Done()
	addr := &net.UDPAddr{IP: net.IPv4zero, Port: d.cfg.DiscoveryPort}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		d.logger.Error("discovery listener failed: %v", err)
		return
	}
	defer conn.Close()
	buf := make([]byte, 1024)
	for {
		if d.isStopping() {
			return
		}
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				select {
				case <-d.stop:
					return
				default:
				}
				continue
			}
			d.logger.Error("discovery read error: %v", err)
			continue
		}
		var ann announcement
		if err := json.Unmarshal(buf[:n], &ann); err != nil {
			d.logger.Error("invalid announcement from %s: %v", remote.IP.String(), err)
			continue
		}
		d.localMu.RLock()
		localIP := d.localIP
		localPort := d.localPort
		d.localMu.RUnlock()
		if ann.IP == localIP && ann.Port == localPort {
			continue
		}
		peer := &Peer{Username: ann.Username, IP: ann.IP, Port: ann.Port, LastSeen: time.Now(), Secret: ann.Secret}
		d.mu.Lock()
		d.peers[peer.IP] = peer
		d.mu.Unlock()
	}
}

func (d *DiscoveryService) announceLoop() {
	defer d.wait.Done()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		d.logger.Error("discovery announcer failed: %v", err)
		return
	}
	defer conn.Close()
	enableBroadcast(conn)
	if err := conn.SetWriteBuffer(1024); err != nil {
		d.logger.Error("discovery write buffer: %v", err)
	}
	d.sendCurrentAnnouncement(conn)
	for {
		select {
		case <-ticker.C:
			d.sendCurrentAnnouncement(conn)
		case <-d.stop:
			return
		}
	}
}

func (d *DiscoveryService) sendCurrentAnnouncement(conn *net.UDPConn) {
	payload, ok := d.prepareAnnouncement()
	if !ok {
		return
	}
	addrs := d.broadcastAddrs()
	d.writeAnnouncement(conn, payload, addrs)
}

func (d *DiscoveryService) prepareAnnouncement() ([]byte, bool) {
	d.localMu.RLock()
	ann := announcement{Username: d.localUser, IP: d.localIP, Port: d.localPort, Timestamp: time.Now().Unix(), Secret: d.cfg.Secret}
	d.localMu.RUnlock()
	if ann.IP == "" || ann.Port == 0 {
		return nil, false
	}
	data, err := json.Marshal(ann)
	if err != nil {
		d.logger.Error("marshal announcement: %v", err)
		return nil, false
	}
	return data, true
}

func (d *DiscoveryService) broadcastAddrs() []*net.UDPAddr {
	seen := make(map[string]struct{})
	var addrs []*net.UDPAddr
	global := &net.UDPAddr{IP: net.IPv4bcast, Port: d.cfg.DiscoveryPort}
	addrs = append(addrs, global)
	seen[global.String()] = struct{}{}
	ifaces, err := net.Interfaces()
	if err != nil {
		d.logger.Error("list interfaces: %v", err)
		return addrs
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagBroadcast == 0 {
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addresses {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipNet.IP.To4()
			if ip == nil || ip.Equal(net.IPv4zero) {
				continue
			}
			mask := ipNet.Mask
			if len(mask) != net.IPv4len {
				continue
			}
			broadcast := net.IPv4(ip[0]|^mask[0], ip[1]|^mask[1], ip[2]|^mask[2], ip[3]|^mask[3])
			if broadcast.Equal(net.IPv4zero) {
				continue
			}
			udpAddr := &net.UDPAddr{IP: broadcast, Port: d.cfg.DiscoveryPort}
			key := udpAddr.String()
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			addrs = append(addrs, udpAddr)
		}
	}
	return addrs
}

func (d *DiscoveryService) writeAnnouncement(conn *net.UDPConn, payload []byte, addrs []*net.UDPAddr) {
	if len(addrs) == 0 {
		addrs = []*net.UDPAddr{{IP: net.IPv4bcast, Port: d.cfg.DiscoveryPort}}
	}
	for _, addr := range addrs {
		if addr == nil {
			continue
		}
		if d.isStopping() {
			return
		}
		if _, err := conn.WriteToUDP(payload, addr); err != nil {
			d.logger.Error("discovery announce to %s: %v", addr, err)
		}
	}
}

func enableBroadcast(conn *net.UDPConn) {
	if conn == nil {
		return
	}
	if raw, err := conn.SyscallConn(); err == nil {
		_ = raw.Control(func(fd uintptr) {
			setBroadcastOption(fd)
		})
	}
}
