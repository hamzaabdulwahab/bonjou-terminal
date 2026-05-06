package network

import (
	"archive/zip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hamzawahab/bonjou-cli/internal/config"
	"github.com/hamzawahab/bonjou-cli/internal/events"
	"github.com/hamzawahab/bonjou-cli/internal/history"
	"github.com/hamzawahab/bonjou-cli/internal/logger"
	"github.com/hamzawahab/bonjou-cli/internal/queue"
)

const (
	kindMessage       = "message"
	kindFileOffer     = "file_offer"
	kindFolderOffer   = "folder_offer"
	kindFileRequest   = "file_request"
	kindFolderRequest = "folder_request"
	kindFileReject    = "file_reject"
	kindFolderReject  = "folder_reject"
	kindFile          = "file"
	kindFolder        = "folder"
	kindAck           = "ack"
	ackTimeout        = 12 * time.Second
)

var (
	errServiceStopping  = errors.New("transfer service stopping")
	errApprovalMissing  = errors.New("transfer approval request not found")
	errTransferRejected = errors.New("transfer was rejected by receiver")
)

type envelope struct {
	Kind       string `json:"kind"`
	From       string `json:"from"`
	FromIP     string `json:"from_ip"`
	To         string `json:"to"`
	Name       string `json:"name"`
	Size       int64  `json:"size"`
	ActualSize int64  `json:"actual_size,omitempty"`
	Timestamp  int64  `json:"ts"`
	Message    string `json:"message"`
	Checksum   string `json:"checksum"`
	HMAC       string `json:"hmac"`
	Encrypted  bool   `json:"encrypted,omitempty"`
	Nonce      string `json:"nonce,omitempty"`
	Encoding   string `json:"encoding,omitempty"`
	AckKind    string `json:"ack_kind,omitempty"`
	AckStatus  string `json:"ack_status,omitempty"`
	RequestID  string `json:"request_id,omitempty"`
	TargetPath string `json:"target_path,omitempty"`
}

type sealedEnvelope struct {
	Nonce    string `json:"nonce"`
	Payload  string `json:"payload"`
	HMAC     string `json:"hmac"`
	Encoding string `json:"encoding,omitempty"`
}

type progressContext struct {
	id        string
	label     string
	path      string
	peer      string
	direction string
	kind      string
}

type outgoingApproval struct {
	Kind       string    `json:"kind"`
	Name       string    `json:"name"`
	Path       string    `json:"path"`
	Size       int64     `json:"size"`
	ActualSize int64     `json:"actual_size"`
	Checksum   string    `json:"checksum"`
	CreatedAt  time.Time `json:"created_at"`
}

type writeDeadlineSetter interface {
	SetWriteDeadline(time.Time) error
}

type readDeadlineSetter interface {
	SetReadDeadline(time.Time) error
}

// TransferService manages TCP message and payload transfers.
type TransferService struct {
	cfg          *config.Config
	logger       *logger.Logger
	history      *history.Manager
	events       chan<- events.Event
	discovery    *DiscoveryService
	queue        *queue.Manager
	listener     net.Listener
	stop         chan struct{}
	stopOnce     sync.Once
	wait         sync.WaitGroup
	localUser    string
	localIP      string
	localMu      sync.RWMutex
	chunkSize    int
	chunkTimeout time.Duration

	pendingAckMu sync.Mutex
	pendingAcks  map[string]chan *envelope

	outgoingMu           sync.Mutex
	outgoingApprovals    map[string]*outgoingApproval
	outgoingSnapshotPath string

	cancelMu     sync.Mutex
	cancelActive chan struct{}
}

func (t *TransferService) isStopping() bool {
	select {
	case <-t.stop:
		return true
	default:
		return false
	}
}

func NewTransferService(cfg *config.Config, logger *logger.Logger, history *history.Manager, events chan<- events.Event, discovery *DiscoveryService, queueMgr *queue.Manager) *TransferService {
	t := &TransferService{
		cfg:                  cfg,
		logger:               logger,
		history:              history,
		events:               events,
		discovery:            discovery,
		queue:                queueMgr,
		stop:                 make(chan struct{}),
		chunkSize:            cfg.ChunkSizeBytes(),
		chunkTimeout:         cfg.ChunkTimeout(),
		pendingAcks:          make(map[string]chan *envelope),
		outgoingApprovals:    make(map[string]*outgoingApproval),
		outgoingSnapshotPath: filepath.Join(cfg.BaseDir, "pending", "outgoing.json"),
	}
	t.loadOutgoingApprovals()
	return t
}

func (t *TransferService) Start(username, ip string) error {
	addr := fmt.Sprintf(":%d", t.cfg.ListenPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		if strings.Contains(err.Error(), "address already in use") {
			return fmt.Errorf("port %d is already in use - another Bonjou instance or application may be running. Error: %v", t.cfg.ListenPort, err)
		}
		if strings.Contains(err.Error(), "permission denied") {
			return fmt.Errorf("permission denied to listen on port %d - you may need to use a port >1024 or run with elevated privileges. Error: %v", t.cfg.ListenPort, err)
		}
		return fmt.Errorf("failed to start transfer service on port %d: %v", t.cfg.ListenPort, err)
	}
	t.listener = ln
	t.localMu.Lock()
	t.localUser = username
	t.localIP = ip
	t.localMu.Unlock()
	t.wait.Add(1)
	go t.acceptLoop()
	return nil
}

func (t *TransferService) Stop() {
	t.stopOnce.Do(func() {
		close(t.stop)
		if t.listener != nil {
			_ = t.listener.Close()
		}
	})
	t.wait.Wait()
}

func (t *TransferService) acceptLoop() {
	defer t.wait.Done()
	for {
		conn, err := t.listener.Accept()
		if err != nil {
			select {
			case <-t.stop:
				return
			default:
			}
			t.logger.Error("accept error: %v", err)
			continue
		}
		t.wait.Add(1)
		go func(c net.Conn) {
			defer t.wait.Done()
			defer c.Close()
			if err := t.handleConnection(c); err != nil {
				if errors.Is(err, errServiceStopping) {
					return
				}
				t.logger.Error("handle connection: %v", err)
			}
		}(conn)
	}
}

func (t *TransferService) handleConnection(conn net.Conn) error {
	if t.isStopping() {
		return errServiceStopping
	}
	env, key, err := t.readSecureEnvelope(conn)
	if err != nil {
		return err
	}
	if err := t.verifyEnvelope(env, key); err != nil {
		t.logger.Error("verify envelope failed: %v", err)
		t.emit(events.Event{Type: events.Error, Title: "Rejected incoming payload", Message: err.Error(), From: env.From, Timestamp: time.Now()})
		return err
	}
	if env.Encrypted && strings.TrimSpace(env.Nonce) == "" {
		return errors.New("encrypted payload missing nonce")
	}

	switch env.Kind {
	case kindMessage:
		if env.Encrypted {
			nonce, err := hex.DecodeString(env.Nonce)
			if err != nil {
				return err
			}
			plaintext, err := decryptText(key, nonce, env.Message, env.Encoding)
			if err != nil {
				return err
			}
			env.Message = plaintext
		}
		env.Message = normalizeMessageLineEndings(env.Message)
		t.emit(events.Event{Type: events.MessageReceived, Title: "Message", Message: env.Message, From: env.From, Timestamp: time.Now()})
		if t.history != nil {
			_ = t.history.AppendChat(env.From, env.To, env.Message)
		}
		return nil
	case kindFileOffer:
		return t.receiveFileOffer(env)
	case kindFolderOffer:
		return t.receiveFolderOffer(env)
	case kindFileRequest:
		return t.handleFileRequest(env)
	case kindFolderRequest:
		return t.handleFolderRequest(env)
	case kindFileReject, kindFolderReject:
		return t.handleTransferRejection(env)
	case kindFile:
		return t.receiveFile(conn, env, key)
	case kindFolder:
		return t.receiveFolder(conn, env, key)
	case kindAck:
		return t.receiveDeliveryAck(env)
	default:
		return fmt.Errorf("unknown payload kind: %s", env.Kind)
	}
}

// SendMessage delivers plain text to a peer.
func (t *TransferService) SendMessage(peer *Peer, message string) error {
	if t.isStopping() {
		return errServiceStopping
	}
	localUser, localIP := t.identity()
	message = normalizeMessageLineEndings(message)
	env := &envelope{
		Kind:      kindMessage,
		From:      localUser,
		FromIP:    localIP,
		To:        peer.Username,
		Message:   message,
		Timestamp: time.Now().Unix(),
	}
	if err := t.sendEnvelope(peer, env, nil); err != nil {
		return err
	}
	t.emit(events.Event{Type: events.MessageSent, Title: "Message sent", Message: message, To: peer.Username, Timestamp: time.Now()})
	if t.history != nil {
		return t.history.AppendChat(localUser, peer.Username, message)
	}
	return nil
}

// SendFile sends metadata first. File bytes are transferred only after receiver approval.
func (t *TransferService) SendFile(peer *Peer, path string) error {
	if t.isStopping() {
		return errServiceStopping
	}
	cancel, finish := t.beginCancelableOperation()
	defer finish()

	localUser, localIP := t.identity()
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("file not found: %s", filepath.Base(path))
		}
		return fmt.Errorf("cannot access file: %v", err)
	}
	if info.IsDir() {
		return errors.New("path is a directory — use @folder to send a folder")
	}
	if err := t.checkCanceled(cancel); err != nil {
		return err
	}
	tf, err := openTransferFile(path)
	if err != nil {
		return fmt.Errorf("cannot read file for transfer: %v", err)
	}
	_ = tf.file.Close()

	requestID, err := randomHexID(16)
	if err != nil {
		return err
	}
	t.storeOutgoingApproval(requestID, &outgoingApproval{
		Kind:      kindFile,
		Name:      filepath.Base(path),
		Path:      path,
		Size:      tf.size,
		Checksum:  tf.checksum,
		CreatedAt: time.Now(),
	})

	env := &envelope{
		Kind:      kindFileOffer,
		From:      localUser,
		FromIP:    localIP,
		To:        peer.Username,
		Name:      filepath.Base(path),
		Size:      tf.size,
		Checksum:  tf.checksum,
		RequestID: requestID,
		Timestamp: time.Now().Unix(),
		Message:   "waiting for receiver approval",
	}
	if err := t.sendEnvelope(peer, env, nil); err != nil {
		t.deleteOutgoingApproval(requestID)
		return err
	}

	t.emit(events.Event{
		Type:      events.Status,
		Title:     "File offer sent",
		Message:   fmt.Sprintf("File offer sent: '%s' to %s. Waiting for approval.", filepath.Base(path), peerLabelOrIP(peer)),
		To:        peer.Username,
		Timestamp: time.Now(),
	})
	return nil
}

// SendFolder sends metadata first. Folder bytes are transferred only after receiver approval.
func (t *TransferService) SendFolder(peer *Peer, dir string) error {
	if t.isStopping() {
		return errServiceStopping
	}
	cancel, finish := t.beginCancelableOperation()
	defer finish()

	localUser, localIP := t.identity()
	info, err := os.Stat(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("folder not found: %s", filepath.Base(dir))
		}
		return fmt.Errorf("cannot access folder: %v", err)
	}
	if !info.IsDir() {
		return errors.New("path is not a directory — use @file to send a single file")
	}

	displayName := filepath.Base(dir)
	t.emit(events.Event{
		Type:      events.Status,
		Title:     "Preparing folder offer",
		Message:   fmt.Sprintf("Preparing folder '%s' for approval...", displayName),
		To:        peer.Username,
		Timestamp: time.Now(),
	})

	actualSize, err := directorySize(dir, cancel)
	if err != nil {
		return fmt.Errorf("failed to measure folder size: %v", err)
	}

	preview, err := folderPreview(dir, cancel)
	if err != nil {
		return fmt.Errorf("failed to build folder preview: %v", err)
	}

	archivePath, err := zipDirectory(dir, cancel)
	if err != nil {
		return fmt.Errorf("failed to compress folder for transfer: %v", err)
	}
	defer os.Remove(archivePath)

	tf, err := openTransferFile(archivePath)
	if err != nil {
		return fmt.Errorf("cannot read compressed archive for transfer: %v", err)
	}
	_ = tf.file.Close()

	requestID, err := randomHexID(16)
	if err != nil {
		return err
	}

	t.storeOutgoingApproval(requestID, &outgoingApproval{
		Kind:       kindFolder,
		Name:       displayName,
		Path:       dir,
		Size:       tf.size,
		ActualSize: actualSize,
		Checksum:   tf.checksum,
		CreatedAt:  time.Now(),
	})

	env := &envelope{
		Kind:       kindFolderOffer,
		From:       localUser,
		FromIP:     localIP,
		To:         peer.Username,
		Name:       displayName,
		Size:       actualSize,
		ActualSize: actualSize,
		Checksum:   tf.checksum,
		RequestID:  requestID,
		Timestamp:  time.Now().Unix(),
		Message:    preview,
	}
	if err := t.sendEnvelope(peer, env, nil); err != nil {
		t.deleteOutgoingApproval(requestID)
		return err
	}

	t.emit(events.Event{
		Type:      events.Status,
		Title:     "Folder offer sent",
		Message:   fmt.Sprintf("Folder offer sent: '%s' to %s. Waiting for approval.", displayName, peerLabelOrIP(peer)),
		To:        peer.Username,
		Timestamp: time.Now(),
	})
	return nil
}

func (t *TransferService) ApproveFileTransfer(f *queue.PendingFile, destPath string) error {
	if f == nil {
		return queue.ErrQueueItemNotFound
	}
	peer, err := t.resolvePeerForQueueItem(f.Sender, f.SenderIP)
	if err != nil {
		return err
	}
	localUser, localIP := t.identity()
	env := &envelope{
		Kind:       kindFileRequest,
		From:       localUser,
		FromIP:     localIP,
		To:         peer.Username,
		Name:       f.Name,
		Size:       f.Size,
		RequestID:  f.RequestID,
		TargetPath: destPath,
		Timestamp:  time.Now().Unix(),
	}
	if err := t.sendEnvelope(peer, env, nil); err != nil {
		return err
	}
	t.emit(events.Event{
		Type:      events.Status,
		Title:     "Download requested",
		Message:   fmt.Sprintf("Requested file '%s' from %s", f.Name, peerLabelOrIP(peer)),
		From:      peer.Username,
		Timestamp: time.Now(),
	})
	return nil
}

func (t *TransferService) ApproveFolderTransfer(f *queue.PendingFolder, destPath string) error {
	if f == nil {
		return queue.ErrQueueItemNotFound
	}
	peer, err := t.resolvePeerForQueueItem(f.Sender, f.SenderIP)
	if err != nil {
		return err
	}
	localUser, localIP := t.identity()
	env := &envelope{
		Kind:       kindFolderRequest,
		From:       localUser,
		FromIP:     localIP,
		To:         peer.Username,
		Name:       f.Name,
		Size:       f.Size,
		RequestID:  f.RequestID,
		TargetPath: destPath,
		Timestamp:  time.Now().Unix(),
	}
	if err := t.sendEnvelope(peer, env, nil); err != nil {
		return err
	}
	t.emit(events.Event{
		Type:      events.Status,
		Title:     "Download requested",
		Message:   fmt.Sprintf("Requested folder '%s' from %s", f.Name, peerLabelOrIP(peer)),
		From:      peer.Username,
		Timestamp: time.Now(),
	})
	return nil
}

func (t *TransferService) RejectFileTransfer(f *queue.PendingFile) error {
	if f == nil {
		return queue.ErrQueueItemNotFound
	}
	return t.sendRejection(kindFileReject, f.RequestID, f.Name, f.Sender, f.SenderIP)
}

func (t *TransferService) RejectFolderTransfer(f *queue.PendingFolder) error {
	if f == nil {
		return queue.ErrQueueItemNotFound
	}
	return t.sendRejection(kindFolderReject, f.RequestID, f.Name, f.Sender, f.SenderIP)
}

func (t *TransferService) sendRejection(kind, requestID, name, sender, senderIP string) error {
	peer, err := t.resolvePeerForQueueItem(sender, senderIP)
	if err != nil {
		return err
	}
	localUser, localIP := t.identity()
	env := &envelope{
		Kind:      kind,
		From:      localUser,
		FromIP:    localIP,
		To:        peer.Username,
		Name:      name,
		RequestID: requestID,
		Timestamp: time.Now().Unix(),
	}
	if err := t.sendEnvelope(peer, env, nil); err != nil {
		return err
	}
	t.emit(events.Event{
		Type:      events.Status,
		Title:     "Transfer rejected",
		Message:   fmt.Sprintf("Rejected %s '%s' from %s", transferKindLabel(kind), name, peerLabelOrIP(peer)),
		From:      peer.Username,
		Timestamp: time.Now(),
	})
	return nil
}

func (t *TransferService) receiveFileOffer(env *envelope) error {
	queueID, err := t.queue.AddFile(env.RequestID, env.From, env.FromIP, env.Name, env.Size, "")
	if err != nil {
		return err
	}
	displayMsg := fmt.Sprintf(
		"Pending file [%d] from %s: %s (%s)\nRun @queue, @view %d, @approve %d, or @reject %d",
		queueID,
		env.From,
		env.Name,
		formatSize(env.Size),
		queueID,
		queueID,
		queueID,
	)
	t.emit(events.Event{
		Type:      events.FilePending,
		Title:     "File pending approval",
		Message:   displayMsg,
		From:      env.From,
		Size:      env.Size,
		Timestamp: time.Now(),
		Level:     "info",
	})
	return nil
}

func (t *TransferService) receiveFolderOffer(env *envelope) error {
	queueID, err := t.queue.AddFolder(env.RequestID, env.From, env.FromIP, env.Name, env.Size, env.Message)
	if err != nil {
		return err
	}
	displayMsg := fmt.Sprintf(
		"Pending folder [%d] from %s: %s (%s)\nRun @queue, @view %d, @approve %d, or @reject %d",
		queueID,
		env.From,
		env.Name,
		formatSize(env.Size),
		queueID,
		queueID,
		queueID,
	)
	t.emit(events.Event{
		Type:      events.FolderPending,
		Title:     "Folder pending approval",
		Message:   displayMsg,
		From:      env.From,
		Size:      env.Size,
		Timestamp: time.Now(),
		Level:     "info",
	})
	return nil
}

func (t *TransferService) handleFileRequest(env *envelope) error {
	approval, ok := t.getOutgoingApproval(env.RequestID)
	if !ok {
		return errApprovalMissing
	}
	if !strings.EqualFold(approval.Kind, kindFile) {
		return fmt.Errorf("approval kind mismatch for request %s", env.RequestID)
	}
	return t.performApprovedFileTransfer(env, approval)
}

func (t *TransferService) handleFolderRequest(env *envelope) error {
	approval, ok := t.getOutgoingApproval(env.RequestID)
	if !ok {
		return errApprovalMissing
	}
	if !strings.EqualFold(approval.Kind, kindFolder) {
		return fmt.Errorf("approval kind mismatch for request %s", env.RequestID)
	}
	return t.performApprovedFolderTransfer(env, approval)
}

func (t *TransferService) handleTransferRejection(env *envelope) error {
	approval, ok := t.getOutgoingApproval(env.RequestID)
	if ok {
		t.deleteOutgoingApproval(env.RequestID)
		t.emit(events.Event{
			Type:      events.Status,
			Title:     "Transfer rejected",
			Message:   fmt.Sprintf("%s '%s' was rejected by %s", transferKindLabel(approval.Kind), approval.Name, safeRemoteLabel(env.From, env.FromIP)),
			From:      env.From,
			Timestamp: time.Now(),
		})
		return nil
	}
	return nil
}

func (t *TransferService) performApprovedFileTransfer(env *envelope, approval *outgoingApproval) error {
	cancel, finish := t.beginCancelableOperation()
	defer finish()

	peer, err := t.resolvePeerForQueueItem(env.From, env.FromIP)
	if err != nil {
		return err
	}
	tf, err := openTransferFile(approval.Path)
	if err != nil {
		return fmt.Errorf("cannot read file for transfer: %v", err)
	}
	defer tf.file.Close()

	localUser, localIP := t.identity()
	sendEnv := &envelope{
		Kind:      kindFile,
		From:      localUser,
		FromIP:    localIP,
		To:        peer.Username,
		Name:      approval.Name,
		Size:      tf.size,
		Checksum:  tf.checksum,
		RequestID: env.RequestID,
		Message:   env.TargetPath,
		Timestamp: time.Now().Unix(),
	}
	stream := func(writer io.Writer, enc cipher.Stream) error {
		ctx := progressContext{
			id:        fmt.Sprintf("file:%s", sendEnv.Name),
			label:     fmt.Sprintf("Sending %s", sendEnv.Name),
			path:      approval.Path,
			peer:      formatPeer(peer),
			direction: "send",
			kind:      kindFile,
		}
		return t.copyWithProgress(writer, enc, tf.file, tf.size, ctx, cancel)
	}
	t.emit(events.Event{
		Type:      events.Status,
		Title:     "Approval received",
		Message:   fmt.Sprintf("%s approved file '%s'. Starting upload...", peerLabelOrIP(peer), approval.Name),
		To:        peer.Username,
		Timestamp: time.Now(),
	})
	t.emit(events.Event{
		Type:      events.FileSent,
		Title:     "File upload started",
		Message:   approval.Name,
		To:        peer.Username,
		Timestamp: time.Now(),
	})
	if err := t.sendEnvelope(peer, sendEnv, stream); err != nil {
		t.emitTransferIssue(kindFile, approval.Name, peer.Username, approval.Path, err)
		return err
	}
	t.deleteOutgoingApproval(env.RequestID)
	if t.history != nil {
		return t.history.AppendTransfer(localUser, peer.Username, approval.Path, tf.size, kindFile)
	}
	return nil
}

func (t *TransferService) performApprovedFolderTransfer(env *envelope, approval *outgoingApproval) error {
	cancel, finish := t.beginCancelableOperation()
	defer finish()

	peer, err := t.resolvePeerForQueueItem(env.From, env.FromIP)
	if err != nil {
		return err
	}
	archivePath, err := zipDirectory(approval.Path, cancel)
	if err != nil {
		return fmt.Errorf("failed to compress folder for transfer: %v", err)
	}
	defer os.Remove(archivePath)

	tf, err := openTransferFile(archivePath)
	if err != nil {
		return fmt.Errorf("cannot read compressed archive for transfer: %v", err)
	}
	defer tf.file.Close()

	localUser, localIP := t.identity()
	sendEnv := &envelope{
		Kind:       kindFolder,
		From:       localUser,
		FromIP:     localIP,
		To:         peer.Username,
		Name:       approval.Name + ".zip",
		Size:       tf.size,
		ActualSize: approval.ActualSize,
		Checksum:   tf.checksum,
		RequestID:  env.RequestID,
		Message:    env.TargetPath,
		Timestamp:  time.Now().Unix(),
	}
	stream := func(writer io.Writer, enc cipher.Stream) error {
		ctx := progressContext{
			id:        fmt.Sprintf("folder:%s", approval.Name),
			label:     fmt.Sprintf("Sending %s", approval.Name),
			path:      approval.Path,
			peer:      formatPeer(peer),
			direction: "send",
			kind:      kindFolder,
		}
		return t.copyWithProgress(writer, enc, tf.file, tf.size, ctx, cancel)
	}
	t.emit(events.Event{
		Type:      events.Status,
		Title:     "Approval received",
		Message:   fmt.Sprintf("%s approved folder '%s'. Starting upload...", peerLabelOrIP(peer), approval.Name),
		To:        peer.Username,
		Timestamp: time.Now(),
	})
	t.emit(events.Event{
		Type:      events.FolderSent,
		Title:     "Folder upload started",
		Message:   approval.Name,
		To:        peer.Username,
		Timestamp: time.Now(),
	})
	if err := t.sendEnvelope(peer, sendEnv, stream); err != nil {
		t.emitTransferIssue(kindFolder, approval.Name, peer.Username, approval.Path, err)
		return err
	}
	t.deleteOutgoingApproval(env.RequestID)
	if t.history != nil {
		return t.history.AppendTransfer(localUser, peer.Username, approval.Path, tf.size, kindFolder)
	}
	return nil
}

func (t *TransferService) sendEnvelope(peer *Peer, env *envelope, writer func(io.Writer, cipher.Stream) error) error {
	if t.isStopping() {
		return errServiceStopping
	}
	if strings.TrimSpace(peer.PublicKey) == "" {
		return errors.New("peer public key unknown; update peer and rediscover")
	}
	shared, err := t.sharedKey(peer.PublicKey)
	if err != nil {
		return err
	}
	var nonceBytes []byte
	if writer != nil || env.Kind == kindMessage {
		nonceBytes, err = randomNonce()
		if err != nil {
			return err
		}
		env.Encrypted = true
		env.Nonce = hex.EncodeToString(nonceBytes)
	}
	if env.Encrypted {
		if env.Kind == kindMessage {
			cipherText, err := encryptText(shared, nonceBytes, env.Message)
			if err != nil {
				return err
			}
			env.Message = cipherText
			env.Encoding = "base64"
		} else {
			env.Encoding = "ctr"
		}
	}
	env.HMAC = t.signEnvelope(env, shared)

	address := net.JoinHostPort(peer.IP, fmt.Sprintf("%d", peer.Port))
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()

	sealed, err := sealEnvelope(env, shared)
	if err != nil {
		return err
	}
	if err := writeEnvelope(conn, sealed); err != nil {
		return err
	}

	if writer == nil {
		return nil
	}
	if t.isStopping() {
		return errServiceStopping
	}

	var ackKey string
	var ackCh chan *envelope
	if env.Kind == kindFile || env.Kind == kindFolder {
		ackKey = deliveryAckKey(env.Kind, transferDisplayName(env.Kind, env.Name), peerLabelOrIP(peer))
		ackCh = t.registerPendingAck(ackKey)
		defer t.unregisterPendingAck(ackKey)
	}

	var stream cipher.Stream
	if env.Encrypted {
		s, err := newCipherStream(shared, nonceBytes)
		if err != nil {
			return err
		}
		stream = s
	}
	if err := writer(conn, stream); err != nil {
		return err
	}
	if env.Kind == kindFile || env.Kind == kindFolder {
		if err := t.awaitInlineDeliveryAck(conn, shared, env); err != nil {
			if ackCh != nil {
				if ack := t.waitPendingAck(ackCh, 2*time.Second); ack != nil {
					if strings.EqualFold(ack.AckStatus, "ok") {
						return nil
					}
					return fmt.Errorf("Delivery failed: %s '%s' to %s", transferKindLabel(env.Kind), transferDisplayName(env.Kind, env.Name), peerLabelOrIP(peer))
				}
			}
			return err
		}
	}
	return nil
}

func (t *TransferService) signEnvelope(env *envelope, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(env.Kind))
	mac.Write([]byte(env.From))
	mac.Write([]byte(env.FromIP))
	mac.Write([]byte(env.To))
	mac.Write([]byte(env.Name))
	mac.Write([]byte(env.Message))
	mac.Write([]byte(env.Checksum))
	mac.Write([]byte(env.RequestID))
	mac.Write([]byte(env.TargetPath))
	sizeBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(sizeBuf, uint64(env.Size))
	mac.Write(sizeBuf)
	actualSizeBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(actualSizeBuf, uint64(env.ActualSize))
	mac.Write(actualSizeBuf)
	tsBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBuf, uint64(env.Timestamp))
	mac.Write(tsBuf)
	if env.Encrypted || env.Nonce != "" || env.Encoding != "" {
		if env.Encrypted {
			mac.Write([]byte{1})
		} else {
			mac.Write([]byte{0})
		}
		mac.Write([]byte(env.Nonce))
		mac.Write([]byte(env.Encoding))
	}
	mac.Write([]byte(env.AckKind))
	mac.Write([]byte(env.AckStatus))
	return hex.EncodeToString(mac.Sum(nil))
}

func (t *TransferService) verifyEnvelope(env *envelope, key []byte) error {
	if len(key) == 0 {
		return errors.New("missing envelope key")
	}
	expected := t.signEnvelope(env, key)
	expectedBytes, err := hex.DecodeString(expected)
	if err != nil {
		return fmt.Errorf("unable to compute signature for %s: %w", env.From, err)
	}
	providedBytes, err := hex.DecodeString(env.HMAC)
	if err != nil {
		return fmt.Errorf("invalid signature data from %s: %w", env.From, err)
	}
	if !hmac.Equal(expectedBytes, providedBytes) {
		return fmt.Errorf("discarded %s from %s (%s): signature mismatch", env.Kind, env.From, env.FromIP)
	}
	return nil
}

func (t *TransferService) receiveFile(conn net.Conn, env *envelope, key []byte) error {
	if t.isStopping() {
		return errServiceStopping
	}
	fileName := filepath.Base(strings.TrimSpace(env.Name))
	if fileName == "" || fileName == "." || fileName == string(os.PathSeparator) {
		return errors.New("invalid file name in transfer")
	}
	destPath := strings.TrimSpace(env.Message)
	if destPath == "" {
		destPath = filepath.Join(t.cfg.ReceivedFilesDir, fileName)
	}
	destPath = queue.UniquePath(destPath)
	if err := ensurePathWithinRoot(destPath, t.cfg.ReceivedFilesDir); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return err
	}
	file, err := os.Create(destPath)
	if err != nil {
		return err
	}
	cleanup := true
	defer func() {
		_ = file.Close()
		if cleanup {
			_ = os.Remove(destPath)
		}
	}()

	hasher := sha256.New()
	defer func() {
		_ = file.Close()
	}()
	ctx := progressContext{
		id:        fmt.Sprintf("recv:%s", fileName),
		label:     fmt.Sprintf("Receiving %s", fileName),
		path:      destPath,
		peer:      formatRemote(env.From, env.FromIP),
		direction: "receive",
		kind:      kindFile,
	}

	var dec cipher.Stream
	if env.Encrypted {
		nonce, err := hex.DecodeString(env.Nonce)
		if err != nil {
			return err
		}
		s, err := newCipherStream(key, nonce)
		if err != nil {
			return err
		}
		dec = s
	}
	if err := t.readWithProgress(conn, dec, file, env.Size, hasher, ctx); err != nil {
		t.emitTransferIssue(kindFile, fileName, env.From, destPath, err)
		return err
	}

	receivedChecksum := hex.EncodeToString(hasher.Sum(nil))
	if !strings.EqualFold(receivedChecksum, env.Checksum) {
		if err := t.writeInlineDeliveryAck(conn, key, env, kindFile, fileName, "error"); err != nil {
			t.sendDeliveryAckOutOfBand(env, kindFile, fileName, "error")
		}
		msg := fmt.Sprintf("File '%s' from %s did not arrive intact — data was corrupted in transit. Please ask them to send it again.", fileName, env.From)
		t.emit(events.Event{Type: events.Error, Title: "Transfer integrity check failed", Message: msg, From: env.From, Timestamp: time.Now(), Path: destPath})
		return fmt.Errorf("transfer integrity check failed for '%s'", fileName)
	}

	if err := file.Close(); err != nil {
		return err
	}
	cleanup = false

	if err := t.writeInlineDeliveryAck(conn, key, env, kindFile, fileName, "ok"); err != nil {
		t.sendDeliveryAckOutOfBand(env, kindFile, fileName, "ok")
	}

	t.emit(events.Event{
		Type:      events.FileReceived,
		Title:     "File received",
		Message:   fileName,
		From:      env.From,
		Path:      destPath,
		Size:      env.Size,
		Timestamp: time.Now(),
	})
	if t.history != nil {
		_ = t.history.AppendTransfer(env.From, t.localUsername(), destPath, env.Size, kindFile)
	}
	return nil
}

func (t *TransferService) receiveFolder(conn net.Conn, env *envelope, key []byte) error {
	if t.isStopping() {
		return errServiceStopping
	}
	pendingDir := filepath.Join(os.TempDir(), "bonjou-pending")
	if err := os.MkdirAll(pendingDir, 0o755); err != nil {
		return err
	}
	archiveName := filepath.Base(strings.TrimSpace(env.Name))
	if archiveName == "" || archiveName == "." || archiveName == string(os.PathSeparator) {
		return errors.New("invalid folder archive name in transfer")
	}
	tempPath := queue.UniquePath(filepath.Join(pendingDir, "raw-"+archiveName))
	if err := ensurePathWithinRoot(tempPath, pendingDir); err != nil {
		return err
	}
	file, err := os.Create(tempPath)
	if err != nil {
		return err
	}
	defer func() {
		_ = file.Close()
		_ = os.Remove(tempPath)
	}()

	destDirName := strings.TrimSuffix(archiveName, ".zip")
	destDir := strings.TrimSpace(env.Message)
	if destDir == "" {
		destDir = filepath.Join(t.cfg.ReceivedFoldersDir, destDirName)
	}
	destDir = queue.UniquePath(destDir)
	if err := ensurePathWithinRoot(destDir, t.cfg.ReceivedFoldersDir); err != nil {
		return err
	}

	hasher := sha256.New()
	ctx := progressContext{
		id:        fmt.Sprintf("recv:%s", archiveName),
		label:     fmt.Sprintf("Receiving %s", destDirName),
		path:      destDir,
		peer:      formatRemote(env.From, env.FromIP),
		direction: "receive",
		kind:      kindFolder,
	}

	var dec cipher.Stream
	if env.Encrypted {
		nonce, err := hex.DecodeString(env.Nonce)
		if err != nil {
			return err
		}
		s, err := newCipherStream(key, nonce)
		if err != nil {
			return err
		}
		dec = s
	}
	if err := t.readWithProgress(conn, dec, file, env.Size, hasher, ctx); err != nil {
		t.emitTransferIssue(kindFolder, destDirName, env.From, destDir, err)
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}

	receivedChecksum := hex.EncodeToString(hasher.Sum(nil))
	if !strings.EqualFold(receivedChecksum, env.Checksum) {
		if err := t.writeInlineDeliveryAck(conn, key, env, kindFolder, destDirName, "error"); err != nil {
			t.sendDeliveryAckOutOfBand(env, kindFolder, destDirName, "error")
		}
		msg := fmt.Sprintf("Folder '%s' from %s did not arrive intact — data was corrupted in transit. Please ask them to send it again.", destDirName, env.From)
		t.emit(events.Event{Type: events.Error, Title: "Transfer integrity check failed", Message: msg, From: env.From, Timestamp: time.Now(), Path: tempPath})
		return fmt.Errorf("transfer integrity check failed for folder '%s'", destDirName)
	}

	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return err
	}
	if err := unzip(tempPath, destDir); err != nil {
		_ = os.RemoveAll(destDir)
		if ackErr := t.writeInlineDeliveryAck(conn, key, env, kindFolder, destDirName, "error"); ackErr != nil {
			t.sendDeliveryAckOutOfBand(env, kindFolder, destDirName, "error")
		}
		return err
	}

	if err := t.writeInlineDeliveryAck(conn, key, env, kindFolder, destDirName, "ok"); err != nil {
		t.sendDeliveryAckOutOfBand(env, kindFolder, destDirName, "ok")
	}

	displaySize := env.Size
	if env.ActualSize > 0 {
		displaySize = env.ActualSize
	}
	t.emit(events.Event{
		Type:      events.FolderReceived,
		Title:     "Folder received",
		Message:   destDirName,
		From:      env.From,
		Path:      destDir,
		Size:      displaySize,
		Timestamp: time.Now(),
	})
	if t.history != nil {
		_ = t.history.AppendTransfer(env.From, t.localUsername(), destDir, displaySize, kindFolder)
	}
	return nil
}

func (t *TransferService) copyWithProgress(writer io.Writer, enc cipher.Stream, reader io.Reader, total int64, ctx progressContext, cancel <-chan struct{}) error {
	chunkSize := t.chunkSize
	if chunkSize <= 0 {
		chunkSize = 64 * 1024
	}
	buf := make([]byte, chunkSize)
	var sent int64
	started := time.Now()
	deadline := t.chunkTimeout
	var setter writeDeadlineSetter
	if deadline > 0 {
		if s, ok := writer.(writeDeadlineSetter); ok {
			setter = s
			defer setter.SetWriteDeadline(time.Time{})
		}
	}
	for {
		if t.isStopping() {
			return errServiceStopping
		}
		if err := t.checkCanceled(cancel); err != nil {
			return err
		}
		n, err := reader.Read(buf)
		if n > 0 {
			payload := buf[:n]
			if enc != nil {
				enc.XORKeyStream(payload, payload)
			}
			if setter != nil && deadline > 0 {
				_ = setter.SetWriteDeadline(time.Now().Add(deadline))
			}
			if _, err := writer.Write(payload); err != nil {
				return err
			}
			sent += int64(n)
			t.emit(events.Event{Type: events.Progress, Progress: &events.ProgressState{
				ID:        ctx.id,
				Label:     ctx.label,
				Path:      ctx.path,
				Peer:      ctx.peer,
				Direction: ctx.direction,
				Kind:      ctx.kind,
				Current:   sent,
				Total:     total,
				StartedAt: started,
				UpdatedAt: time.Now(),
			}})
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	t.emit(events.Event{Type: events.Progress, Progress: &events.ProgressState{
		ID:        ctx.id,
		Label:     ctx.label,
		Path:      ctx.path,
		Peer:      ctx.peer,
		Direction: ctx.direction,
		Kind:      ctx.kind,
		Current:   total,
		Total:     total,
		StartedAt: started,
		UpdatedAt: time.Now(),
		Done:      true,
	}})
	return nil
}

func (t *TransferService) readWithProgress(reader io.Reader, dec cipher.Stream, writer io.Writer, total int64, hash io.Writer, ctx progressContext) error {
	chunkSize := t.chunkSize
	if chunkSize <= 0 {
		chunkSize = 64 * 1024
	}
	buf := make([]byte, chunkSize)
	var received int64
	multiWriter := io.MultiWriter(writer, hash)
	started := time.Now()
	deadline := t.chunkTimeout
	var setter readDeadlineSetter
	if deadline > 0 {
		if s, ok := reader.(readDeadlineSetter); ok {
			setter = s
			defer setter.SetReadDeadline(time.Time{})
		}
	}
	for received < total {
		if t.isStopping() {
			return errServiceStopping
		}
		remaining := total - received
		chunk := buf
		if int64(len(chunk)) > remaining {
			chunk = buf[:remaining]
		}
		if setter != nil && deadline > 0 {
			_ = setter.SetReadDeadline(time.Now().Add(deadline))
		}
		n, err := io.ReadFull(reader, chunk)
		if err != nil {
			return err
		}
		payload := chunk[:n]
		if dec != nil {
			dec.XORKeyStream(payload, payload)
		}
		if _, err := multiWriter.Write(payload); err != nil {
			return err
		}
		received += int64(n)
		if !strings.EqualFold(ctx.direction, "receive") {
			t.emit(events.Event{Type: events.Progress, Progress: &events.ProgressState{
				ID:        ctx.id,
				Label:     ctx.label,
				Path:      ctx.path,
				Peer:      ctx.peer,
				Direction: ctx.direction,
				Kind:      ctx.kind,
				Current:   received,
				Total:     total,
				StartedAt: started,
				UpdatedAt: time.Now(),
			}})
		}
	}
	if !strings.EqualFold(ctx.direction, "receive") {
		t.emit(events.Event{Type: events.Progress, Progress: &events.ProgressState{
			ID:        ctx.id,
			Label:     ctx.label,
			Path:      ctx.path,
			Peer:      ctx.peer,
			Direction: ctx.direction,
			Kind:      ctx.kind,
			Current:   total,
			Total:     total,
			StartedAt: started,
			UpdatedAt: time.Now(),
			Done:      true,
		}})
	}
	return nil
}

func (t *TransferService) emit(evt events.Event) {
	if evt.Type == events.Progress {
		select {
		case t.events <- evt:
		default:
		}
		return
	}
	select {
	case t.events <- evt:
	default:
		timer := time.NewTimer(500 * time.Millisecond)
		defer timer.Stop()
		select {
		case t.events <- evt:
		case <-timer.C:
			t.logger.Error("dropping event %s because the event channel is saturated", evt.Type)
		}
	}
}

func (t *TransferService) receiveDeliveryAck(env *envelope) error {
	t.notifyPendingAck(env)
	t.renderDeliveryAck(env)
	return nil
}

func (t *TransferService) awaitInlineDeliveryAck(conn net.Conn, shared []byte, sent *envelope) error {
	if conn == nil {
		return errors.New("missing transfer connection")
	}
	if setter, ok := conn.(readDeadlineSetter); ok {
		_ = setter.SetReadDeadline(time.Now().Add(ackTimeout))
		defer setter.SetReadDeadline(time.Time{})
	}
	frame, err := readEnvelope(conn)
	if err != nil {
		return fmt.Errorf("no delivery confirmation from '%s' for %s '%s' — the transfer may or may not have completed", sent.To, transferKindLabel(sent.Kind), transferDisplayName(sent.Kind, sent.Name))
	}
	ack, err := openEnvelope(frame, shared)
	if err != nil {
		return fmt.Errorf("invalid delivery confirmation: %w", err)
	}
	if ack.Kind != kindAck {
		return fmt.Errorf("unexpected response kind '%s' during transfer confirmation", ack.Kind)
	}
	if err := t.verifyEnvelopeWithKey(ack, shared); err != nil {
		return fmt.Errorf("invalid delivery confirmation signature: %w", err)
	}
	if ack.AckKind != "" && !strings.EqualFold(ack.AckKind, sent.Kind) {
		return fmt.Errorf("delivery confirmation kind mismatch: sent=%s confirmed=%s", sent.Kind, ack.AckKind)
	}
	t.renderDeliveryAck(ack)
	if !strings.EqualFold(ack.AckStatus, "ok") {
		return fmt.Errorf("Delivery failed: %s '%s' to %s", transferKindLabel(sent.Kind), transferDisplayName(sent.Kind, sent.Name), strings.TrimSpace(sent.To))
	}
	return nil
}

func (t *TransferService) writeInlineDeliveryAck(conn net.Conn, key []byte, source *envelope, kind, name, status string) error {
	if conn == nil {
		return errors.New("missing transfer connection")
	}
	localUser, localIP := t.identity()
	ack := &envelope{
		Kind:      kindAck,
		From:      localUser,
		FromIP:    localIP,
		To:        source.From,
		Name:      name,
		Timestamp: time.Now().Unix(),
		AckKind:   kind,
		AckStatus: status,
	}
	ack.HMAC = t.signEnvelope(ack, key)
	sealed, err := sealEnvelope(ack, key)
	if err != nil {
		return err
	}
	return writeEnvelope(conn, sealed)
}

func (t *TransferService) verifyEnvelopeWithKey(env *envelope, key []byte) error {
	expected := t.signEnvelope(env, key)
	expectedBytes, err := hex.DecodeString(expected)
	if err != nil {
		return fmt.Errorf("unable to compute signature: %w", err)
	}
	providedBytes, err := hex.DecodeString(env.HMAC)
	if err != nil {
		return fmt.Errorf("invalid signature data: %w", err)
	}
	if !hmac.Equal(expectedBytes, providedBytes) {
		return errors.New("signature mismatch")
	}
	return nil
}

func (t *TransferService) renderDeliveryAck(env *envelope) {
	kindLabel := transferKindLabel(env.AckKind)
	name := strings.TrimSpace(env.Name)
	if name == "" {
		name = "payload"
	}
	peer := strings.TrimSpace(env.From)
	if peer == "" {
		peer = "peer"
	}
	if strings.EqualFold(env.AckStatus, "ok") {
		message := fmt.Sprintf("Delivered: %s '%s' to %s", kindLabel, name, peer)
		title := "Delivery confirmed"
		t.emit(events.Event{
			Type:      events.Status,
			Title:     title,
			Message:   message,
			From:      env.From,
			Timestamp: time.Now(),
		})
		return
	}
	t.emit(events.Event{
		Type:      events.Error,
		Title:     "Delivery failed",
		Message:   fmt.Sprintf("Delivery failed: %s '%s' to %s", kindLabel, name, peer),
		From:      env.From,
		Timestamp: time.Now(),
	})
}

func (t *TransferService) sendDeliveryAckOutOfBand(source *envelope, kind, name, status string) {
	peer, err := t.resolvePeerForAck(source)
	if err != nil {
		t.logger.Error("delivery ack fallback resolve peer: %v", err)
		return
	}
	localUser, localIP := t.identity()
	ack := &envelope{
		Kind:      kindAck,
		From:      localUser,
		FromIP:    localIP,
		To:        source.From,
		Name:      transferDisplayName(kind, name),
		Timestamp: time.Now().Unix(),
		AckKind:   kind,
		AckStatus: status,
	}
	if err := t.sendEnvelope(peer, ack, nil); err != nil {
		t.logger.Error("delivery ack fallback send failed: %v", err)
	}
}

func (t *TransferService) resolvePeerForAck(source *envelope) (*Peer, error) {
	ip := strings.TrimSpace(source.FromIP)
	if ip == "" {
		return nil, errors.New("missing sender ip for ack")
	}
	if t.discovery != nil {
		if peer, err := t.discovery.Resolve(ip); err == nil {
			return peer, nil
		}
	}
	if t.discovery == nil {
		return nil, errors.New("discovery service unavailable")
	}
	publicKey, ok := t.discovery.SharedPublicKey(source.From, ip)
	if !ok || strings.TrimSpace(publicKey) == "" {
		return nil, fmt.Errorf("peer key unavailable for %s (%s)", source.From, ip)
	}
	return &Peer{Username: source.From, IP: ip, Port: t.cfg.ListenPort, PublicKey: publicKey}, nil
}

func (t *TransferService) resolvePeerForQueueItem(sender, senderIP string) (*Peer, error) {
	ip := strings.TrimSpace(senderIP)
	if ip == "" {
		return nil, errors.New("missing sender ip")
	}
	if t.discovery != nil {
		if peer, err := t.discovery.Resolve(ip); err == nil {
			return peer, nil
		}
	}
	if t.discovery == nil {
		return nil, errors.New("discovery service unavailable")
	}
	publicKey, ok := t.discovery.SharedPublicKey(sender, ip)
	if !ok || strings.TrimSpace(publicKey) == "" {
		return nil, fmt.Errorf("peer key unavailable for %s (%s)", sender, ip)
	}
	return &Peer{Username: sender, IP: ip, Port: t.cfg.ListenPort, PublicKey: publicKey}, nil
}

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

func (t *TransferService) registerPendingAck(key string) chan *envelope {
	ch := make(chan *envelope, 1)
	t.pendingAckMu.Lock()
	t.pendingAcks[key] = ch
	t.pendingAckMu.Unlock()
	return ch
}

func (t *TransferService) unregisterPendingAck(key string) {
	t.pendingAckMu.Lock()
	delete(t.pendingAcks, key)
	t.pendingAckMu.Unlock()
}

func (t *TransferService) notifyPendingAck(env *envelope) {
	peer := strings.TrimSpace(env.From)
	if peer == "" {
		peer = strings.TrimSpace(env.FromIP)
	}
	key := deliveryAckKey(env.AckKind, transferDisplayName(env.AckKind, env.Name), peer)
	t.pendingAckMu.Lock()
	ch := t.pendingAcks[key]
	t.pendingAckMu.Unlock()
	if ch == nil {
		return
	}
	select {
	case ch <- env:
	default:
	}
}

func (t *TransferService) waitPendingAck(ch chan *envelope, timeout time.Duration) *envelope {
	if ch == nil {
		return nil
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case ack, ok := <-ch:
		if !ok {
			return nil
		}
		return ack
	case <-timer.C:
		return nil
	}
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

func humanizeTransferError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "connection refused"):
		return "peer is not reachable (connection refused) — check they are running Bonjou on the same network"
	case strings.Contains(msg, "no route to host"):
		return "peer is not reachable — check your network connection"
	case strings.Contains(msg, "broken pipe") || strings.Contains(msg, "use of closed network connection"):
		return "connection was lost mid-transfer — please try again"
	case strings.Contains(msg, "reset by peer"):
		return "peer closed the connection unexpectedly — please try again"
	case strings.Contains(msg, "no such file") || strings.Contains(msg, "file not found"):
		return "file no longer exists at the specified path"
	case strings.Contains(msg, "permission denied"):
		return "permission denied — check file and folder permissions"
	case strings.Contains(msg, "no delivery confirmation"):
		return "upload finished, but delivery could not be confirmed — the transfer may or may not have completed on the peer"
	case strings.Contains(msg, "integrity check failed"),
		strings.Contains(msg, "Delivery failed"):
		return msg
	case strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline exceeded"):
		return "connection timed out — check the peer is still reachable"
	default:
		return msg
	}
}

func (t *TransferService) emitTransferIssue(kind, name, peer, path string, err error) {
	if err == nil {
		return
	}
	label := strings.TrimSpace(name)
	if label == "" {
		label = "payload"
	}
	who := strings.TrimSpace(peer)
	if who == "" {
		who = "peer"
	}
	message := humanizeTransferError(err)
	if message == "" {
		message = err.Error()
	}
	t.emit(events.Event{
		Type:      events.Error,
		Title:     "Transfer failed",
		Message:   fmt.Sprintf("Failed to send %s '%s' to %s: %s", strings.ToLower(transferKindLabel(kind)), label, who, message),
		To:        who,
		Path:      path,
		Timestamp: time.Now(),
	})
}

func writeEnvelope(conn net.Conn, data []byte) error {
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(data)))
	if _, err := conn.Write(header); err != nil {
		return err
	}
	if _, err := conn.Write(data); err != nil {
		return err
	}
	return nil
}

func readEnvelope(conn net.Conn) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header)
	if size == 0 {
		return nil, errors.New("empty envelope")
	}
	frame := make([]byte, size)
	if _, err := io.ReadFull(conn, frame); err != nil {
		return nil, err
	}
	return frame, nil
}

func (t *TransferService) readSecureEnvelope(conn net.Conn) (*envelope, []byte, error) {
	frame, err := readEnvelope(conn)
	if err != nil {
		return nil, nil, err
	}
	remoteIPs := remoteIPCandidates(conn)
	if len(remoteIPs) == 0 {
		return nil, nil, errors.New("unable to resolve remote address")
	}
	if t.discovery == nil {
		return nil, nil, errors.New("discovery service unavailable")
	}

	var shared []byte
	for _, ip := range remoteIPs {
		publicKey, ok := t.discovery.SharedPublicKey("", ip)
		if !ok || strings.TrimSpace(publicKey) == "" {
			continue
		}
		key, err := t.sharedKey(publicKey)
		if err != nil {
			continue
		}
		env, err := openEnvelope(frame, key)
		if err == nil {
			return env, key, nil
		}
		shared = key
	}
	if shared == nil {
		return nil, nil, errors.New("unable to derive shared key")
	}

	env, err := openEnvelope(frame, shared)
	if err != nil {
		return nil, nil, err
	}
	return env, shared, nil
}

func sealEnvelope(env *envelope, shared []byte) ([]byte, error) {
	plain, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	nonce, err := randomNonce()
	if err != nil {
		return nil, err
	}
	stream, err := newCipherStream(shared, nonce)
	if err != nil {
		return nil, err
	}
	payload := make([]byte, len(plain))
	copy(payload, plain)
	stream.XORKeyStream(payload, payload)
	mac := hmac.New(sha256.New, shared)
	mac.Write(payload)
	sealed := sealedEnvelope{
		Nonce:    hex.EncodeToString(nonce),
		Payload:  base64.StdEncoding.EncodeToString(payload),
		HMAC:     hex.EncodeToString(mac.Sum(nil)),
		Encoding: "base64",
	}
	return json.Marshal(sealed)
}

func openEnvelope(frame []byte, shared []byte) (*envelope, error) {
	var sealed sealedEnvelope
	if err := json.Unmarshal(frame, &sealed); err != nil {
		return nil, err
	}
	if sealed.Encoding != "" && sealed.Encoding != "base64" {
		return nil, fmt.Errorf("unsupported envelope encoding: %s", sealed.Encoding)
	}
	nonce, err := hex.DecodeString(sealed.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decode envelope nonce: %w", err)
	}
	payload, err := base64.StdEncoding.DecodeString(sealed.Payload)
	if err != nil {
		return nil, fmt.Errorf("decode envelope payload: %w", err)
	}
	mac := hmac.New(sha256.New, shared)
	mac.Write(payload)
	expectedMAC := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expectedMAC), []byte(sealed.HMAC)) {
		return nil, errors.New("sealed envelope hmac mismatch")
	}
	stream, err := newCipherStream(shared, nonce)
	if err != nil {
		return nil, err
	}
	plain := make([]byte, len(payload))
	copy(plain, payload)
	stream.XORKeyStream(plain, plain)

	var env envelope
	if err := json.Unmarshal(plain, &env); err != nil {
		return nil, err
	}
	return &env, nil
}

func newCipherStream(key, nonce []byte) (cipher.Stream, error) {
	if len(key) < 32 {
		return nil, errors.New("shared key too short")
	}
	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return nil, err
	}
	if len(nonce) < aes.BlockSize {
		return nil, errors.New("nonce too short")
	}
	return cipher.NewCTR(block, nonce[:aes.BlockSize]), nil
}

func randomNonce() ([]byte, error) {
	nonce := make([]byte, aes.BlockSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

func randomHexID(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func encryptText(shared, nonce []byte, plain string) (string, error) {
	stream, err := newCipherStream(shared, nonce)
	if err != nil {
		return "", err
	}
	buf := []byte(plain)
	out := make([]byte, len(buf))
	copy(out, buf)
	stream.XORKeyStream(out, out)
	return base64.StdEncoding.EncodeToString(out), nil
}

func decryptText(shared, nonce []byte, cipherText, encoding string) (string, error) {
	if encoding != "" && encoding != "base64" {
		return "", fmt.Errorf("unsupported text encoding: %s", encoding)
	}
	payload, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}
	stream, err := newCipherStream(shared, nonce)
	if err != nil {
		return "", err
	}
	out := make([]byte, len(payload))
	copy(out, payload)
	stream.XORKeyStream(out, out)
	return string(out), nil
}

func (t *TransferService) sharedKey(remotePublicKey string) ([]byte, error) {
	localKey, err := privateKeyFromSecret(t.cfg.Secret)
	if err != nil {
		return nil, err
	}
	remoteBytes, err := hex.DecodeString(strings.TrimSpace(remotePublicKey))
	if err != nil {
		return nil, err
	}
	curve := ecdh.X25519()
	remoteKey, err := curve.NewPublicKey(remoteBytes)
	if err != nil {
		return nil, err
	}
	shared, err := localKey.ECDH(remoteKey)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(shared)
	return sum[:], nil
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

func (t *TransferService) identity() (string, string) {
	t.localMu.RLock()
	defer t.localMu.RUnlock()
	return t.localUser, t.localIP
}

// UpdateLocalUser swaps the local username used for outgoing transfers.
func (t *TransferService) UpdateLocalUser(username string) {
	t.localMu.Lock()
	t.localUser = username
	t.localMu.Unlock()
}

// UpdateLocalEndpoint updates cached identity fields following network changes.
func (t *TransferService) UpdateLocalEndpoint(username, ip string) {
	t.localMu.Lock()
	if username != "" {
		t.localUser = username
	}
	if ip != "" {
		t.localIP = ip
	}
	t.localMu.Unlock()
}

func (t *TransferService) localUsername() string {
	t.localMu.RLock()
	defer t.localMu.RUnlock()
	return t.localUser
}

func (t *TransferService) storeOutgoingApproval(requestID string, approval *outgoingApproval) {
	t.outgoingMu.Lock()
	t.outgoingApprovals[requestID] = approval
	_ = t.saveOutgoingApprovalsLocked()
	t.outgoingMu.Unlock()
}

func (t *TransferService) getOutgoingApproval(requestID string) (*outgoingApproval, bool) {
	t.outgoingMu.Lock()
	defer t.outgoingMu.Unlock()
	approval, ok := t.outgoingApprovals[requestID]
	if !ok {
		return nil, false
	}
	copy := *approval
	return &copy, true
}

func (t *TransferService) deleteOutgoingApproval(requestID string) {
	t.outgoingMu.Lock()
	delete(t.outgoingApprovals, requestID)
	_ = t.saveOutgoingApprovalsLocked()
	t.outgoingMu.Unlock()
}

func (t *TransferService) loadOutgoingApprovals() {
	if err := os.MkdirAll(filepath.Dir(t.outgoingSnapshotPath), 0o755); err != nil {
		t.logger.Error("prepare outgoing approval directory: %v", err)
		return
	}

	data, err := os.ReadFile(t.outgoingSnapshotPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			t.logger.Error("read outgoing approvals: %v", err)
		}
		return
	}

	var snapshot map[string]*outgoingApproval
	if err := json.Unmarshal(data, &snapshot); err != nil {
		t.logger.Error("decode outgoing approvals: %v", err)
		return
	}

	t.outgoingMu.Lock()
	defer t.outgoingMu.Unlock()

	for requestID, approval := range snapshot {
		if approval == nil {
			continue
		}
		if strings.TrimSpace(requestID) == "" || strings.TrimSpace(approval.Path) == "" {
			continue
		}
		info, err := os.Stat(approval.Path)
		if err != nil {
			continue
		}
		switch approval.Kind {
		case kindFile:
			if info.IsDir() {
				continue
			}
		case kindFolder:
			if !info.IsDir() {
				continue
			}
		default:
			continue
		}
		copy := *approval
		t.outgoingApprovals[requestID] = &copy
	}
}

func (t *TransferService) saveOutgoingApprovalsLocked() error {
	if err := os.MkdirAll(filepath.Dir(t.outgoingSnapshotPath), 0o755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(t.outgoingApprovals, "", "  ")
	if err != nil {
		return err
	}

	tempPath := t.outgoingSnapshotPath + ".tmp"
	if err := os.WriteFile(tempPath, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tempPath, t.outgoingSnapshotPath); err != nil {
		_ = os.Remove(tempPath)
		return err
	}
	return nil
}

func (t *TransferService) beginCancelableOperation() (<-chan struct{}, func()) {
	t.cancelMu.Lock()
	cancel := make(chan struct{})
	t.cancelActive = cancel
	t.cancelMu.Unlock()

	return cancel, func() {
		t.cancelMu.Lock()
		if t.cancelActive == cancel {
			t.cancelActive = nil
		}
		t.cancelMu.Unlock()
	}
}

func (t *TransferService) CancelActiveOperation() bool {
	t.cancelMu.Lock()
	defer t.cancelMu.Unlock()
	if t.cancelActive == nil {
		return false
	}
	close(t.cancelActive)
	t.cancelActive = nil
	return true
}

func (t *TransferService) checkCanceled(cancel <-chan struct{}) error {
	if cancel == nil {
		return nil
	}
	select {
	case <-cancel:
		return errors.New("operation cancelled")
	default:
		return nil
	}
}

func ensurePathWithinRoot(path, root string) error {
	cleanRoot := filepath.Clean(root)
	cleanPath := filepath.Clean(path)
	rel, err := filepath.Rel(cleanRoot, cleanPath)
	if err != nil {
		return err
	}
	if rel == "." {
		return nil
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("path traversal not allowed: %s escapes %s", cleanPath, cleanRoot)
	}
	return nil
}

func formatSize(size int64) string {
	const unit = 1000
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(size)/float64(div), "KMGTPE"[exp])
}

func folderPreview(root string, cancel <-chan struct{}) (string, error) {
	type item struct {
		path  string
		isDir bool
	}
	var items []item
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		select {
		case <-cancel:
			return errors.New("operation cancelled")
		default:
		}
		if path == root {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil
		}
		items = append(items, item{path: filepath.ToSlash(rel), isDir: d.IsDir()})
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].isDir != items[j].isDir {
			return items[i].isDir
		}
		return strings.ToLower(items[i].path) < strings.ToLower(items[j].path)
	})
	if len(items) == 0 {
		return "(empty)", nil
	}
	maxLines := 64
	var lines []string
	for i, item := range items {
		if i >= maxLines {
			lines = append(lines, fmt.Sprintf("... and %d more entries", len(items)-maxLines))
			break
		}
		if item.isDir {
			lines = append(lines, item.path+"/")
		} else {
			lines = append(lines, item.path)
		}
	}
	return strings.Join(lines, "\n"), nil
}

func zipDirectory(dir string, cancel <-chan struct{}) (string, error) {
	tempFile, err := os.CreateTemp("", "bonjou-folder-*.zip")
	if err != nil {
		return "", err
	}
	tempPath := tempFile.Name()
	zw := zip.NewWriter(tempFile)

	err = filepath.Walk(dir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		select {
		case <-cancel:
			return errors.New("operation cancelled")
		default:
		}
		if path == dir {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		header.Name = rel
		if info.IsDir() {
			header.Name += "/"
		} else {
			header.Method = zip.Deflate
		}

		writer, err := zw.CreateHeader(header)
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(writer, file)
		closeErr := file.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		return nil
	})

	closeErr := zw.Close()
	fileCloseErr := tempFile.Close()

	if err != nil {
		_ = os.Remove(tempPath)
		return "", err
	}
	if closeErr != nil {
		_ = os.Remove(tempPath)
		return "", closeErr
	}
	if fileCloseErr != nil {
		_ = os.Remove(tempPath)
		return "", fileCloseErr
	}
	return tempPath, nil
}

func directorySize(root string, cancel <-chan struct{}) (int64, error) {
	var total int64
	err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		select {
		case <-cancel:
			return errors.New("operation cancelled")
		default:
		}
		if info == nil || info.IsDir() {
			return nil
		}
		total += info.Size()
		return nil
	})
	if err != nil {
		return 0, err
	}
	return total, nil
}

func unzip(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, file := range r.File {
		targetPath := filepath.Join(dest, filepath.FromSlash(file.Name))
		if err := ensurePathWithinRoot(targetPath, dest); err != nil {
			return err
		}
		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(targetPath, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
			return err
		}
		rc, err := file.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, file.Mode())
		if err != nil {
			_ = rc.Close()
			return err
		}
		if _, err := io.Copy(out, rc); err != nil {
			_ = out.Close()
			_ = rc.Close()
			return err
		}
		if err := out.Close(); err != nil {
			_ = rc.Close()
			return err
		}
		if err := rc.Close(); err != nil {
			return err
		}
	}
	return nil
}

type transferFile struct {
	file     *os.File
	size     int64
	checksum string
}

// openTransferFile opens path once, reads through it to compute its
// SHA-256 checksum, then seeks back to the beginning so the caller can
// stream the exact same bytes to the network.
func openTransferFile(path string) (*transferFile, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		_ = file.Close()
		return nil, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		return nil, err
	}
	return &transferFile{
		file:     file,
		size:     info.Size(),
		checksum: hex.EncodeToString(hasher.Sum(nil)),
	}, nil
}
