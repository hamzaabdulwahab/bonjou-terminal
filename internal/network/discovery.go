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
}

type announcement struct {
	Username  string `json:"username"`
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	Timestamp int64  `json:"ts"`
}

// DiscoveryService handles LAN peer discovery over UDP broadcasts.
type DiscoveryService struct {
	cfg       *config.Config
	logger    *logger.Logger
	peers     map[string]*Peer
	mu        sync.RWMutex
	stop      chan struct{}
	stopOnce  sync.Once
	wait      sync.WaitGroup
	started   bool
	localUser string
	localIP   string
	localPort int
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
	d.localUser = username
	d.localIP = ip
	d.localPort = port
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
		out = append(out, *peer)
	}
	return out
}

// Resolve takes a username or IP string and returns the matching peer.
func (d *DiscoveryService) Resolve(target string) (*Peer, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	// direct IP match first
	if peer, ok := d.peers[target]; ok {
		return &Peer{Username: peer.Username, IP: peer.IP, Port: peer.Port, LastSeen: peer.LastSeen}, nil
	}
	for _, peer := range d.peers {
		if peer.Username == target {
			return &Peer{Username: peer.Username, IP: peer.IP, Port: peer.Port, LastSeen: peer.LastSeen}, nil
		}
	}
	return nil, errors.New("peer not found")
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
		if ann.IP == d.localIP && ann.Port == d.localPort {
			continue
		}
		peer := &Peer{Username: ann.Username, IP: ann.IP, Port: ann.Port, LastSeen: time.Now()}
		d.mu.Lock()
		d.peers[peer.IP] = peer
		d.mu.Unlock()
	}
}

func (d *DiscoveryService) announceLoop() {
	defer d.wait.Done()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	broadcastAddr := &net.UDPAddr{IP: net.IPv4bcast, Port: d.cfg.DiscoveryPort}
	payload := func() []byte {
		ann := announcement{Username: d.localUser, IP: d.localIP, Port: d.localPort, Timestamp: time.Now().Unix()}
		data, _ := json.Marshal(ann)
		return data
	}
	conn, err := net.DialUDP("udp4", nil, broadcastAddr)
	if err != nil {
		d.logger.Error("discovery announcer failed: %v", err)
		return
	}
	defer conn.Close()
	if err := conn.SetWriteBuffer(1024); err != nil {
		d.logger.Error("discovery write buffer: %v", err)
	}
	for {
		if _, err := conn.Write(payload()); err != nil {
			d.logger.Error("discovery announce error: %v", err)
		}
		select {
		case <-ticker.C:
		case <-d.stop:
			return
		}
	}
}
