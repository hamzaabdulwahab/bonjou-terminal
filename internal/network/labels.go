package network

import (
	"fmt"
	"net"
	"strings"
)

// Small, dependency-free helpers that turn protocol identifiers and Peer
// values into the human-readable labels we splice into envelopes, events,
// and log lines. Kept in one file so reviewing the user-visible vocabulary
// is a single read.

func deliveryAckKey(kind, name, peer string) string {
	return strings.ToLower(strings.TrimSpace(kind)) + "|" + strings.ToLower(strings.TrimSpace(name)) + "|" + strings.ToLower(strings.TrimSpace(peer))
}

func peerLabelOrIP(peer *Peer) string {
	if peer == nil {
		return "peer"
	}
	if strings.TrimSpace(peer.Username) != "" {
		return strings.TrimSpace(peer.Username)
	}
	if strings.TrimSpace(peer.IP) != "" {
		return strings.TrimSpace(peer.IP)
	}
	return "peer"
}

func transferKindLabel(kind string) string {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case kindFolder, kindFolderOffer, kindFolderRequest, kindFolderReject:
		return "Folder"
	case kindFile, kindFileOffer, kindFileRequest, kindFileReject:
		return "File"
	case kindMessage:
		return "Message"
	default:
		return "Transfer"
	}
}

func transferDisplayName(kind, name string) string {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return "payload"
	}
	if strings.EqualFold(strings.TrimSpace(kind), kindFolder) || strings.EqualFold(strings.TrimSpace(kind), kindFolderOffer) || strings.EqualFold(strings.TrimSpace(kind), kindFolderRequest) || strings.EqualFold(strings.TrimSpace(kind), kindFolderReject) {
		return strings.TrimSuffix(trimmed, ".zip")
	}
	return trimmed
}

func normalizeMessageLineEndings(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return s
}

func remoteIPCandidates(conn net.Conn) []string {
	if conn == nil {
		return nil
	}
	addr := conn.RemoteAddr()
	if addr == nil {
		return nil
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	if ip := net.ParseIP(host); ip != nil {
		return []string{ip.String()}
	}
	return nil
}

func formatPeer(peer *Peer) string {
	if peer == nil {
		return "peer"
	}
	if strings.TrimSpace(peer.Username) != "" {
		if strings.TrimSpace(peer.IP) != "" {
			return fmt.Sprintf("%s (%s)", peer.Username, peer.IP)
		}
		return peer.Username
	}
	if strings.TrimSpace(peer.IP) != "" {
		return peer.IP
	}
	return "peer"
}

func formatRemote(user, ip string) string {
	if strings.TrimSpace(user) != "" && strings.TrimSpace(ip) != "" {
		return fmt.Sprintf("%s (%s)", user, ip)
	}
	if strings.TrimSpace(user) != "" {
		return user
	}
	if strings.TrimSpace(ip) != "" {
		return ip
	}
	return "peer"
}

func safeRemoteLabel(user, ip string) string {
	label := formatRemote(user, ip)
	if strings.TrimSpace(label) == "" {
		return "peer"
	}
	return label
}
