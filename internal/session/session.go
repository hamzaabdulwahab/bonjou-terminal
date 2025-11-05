package session

import (
	"github.com/hamzawahab/bonjou-terminal/internal/config"
	"github.com/hamzawahab/bonjou-terminal/internal/events"
	"github.com/hamzawahab/bonjou-terminal/internal/history"
	"github.com/hamzawahab/bonjou-terminal/internal/logger"
	"github.com/hamzawahab/bonjou-terminal/internal/network"
)

// Session wires together Bonjou runtime services.
type Session struct {
	Config    *config.Config
	Logger    *logger.Logger
	History   *history.Manager
	Discovery *network.DiscoveryService
	Transfer  *network.TransferService
	Events    chan events.Event
	LocalIP   string
}

func New(cfg *config.Config, log *logger.Logger, hist *history.Manager, disc *network.DiscoveryService, transfer *network.TransferService, events chan events.Event, ip string) *Session {
	return &Session{
		Config:    cfg,
		Logger:    log,
		History:   hist,
		Discovery: disc,
		Transfer:  transfer,
		Events:    events,
		LocalIP:   ip,
	}
}

// Close releases resources associated with the session.
func (s *Session) Close() {
	if s.Transfer != nil {
		s.Transfer.Stop()
	}
	if s.Discovery != nil {
		s.Discovery.Stop()
	}
	if s.Logger != nil {
		_ = s.Logger.Close()
	}
}
