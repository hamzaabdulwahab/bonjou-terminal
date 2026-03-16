package network

import (
	"archive/zip"
	"crypto/aes"
	"crypto/cipher"
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
	"strings"
	"sync"
	"time"

	"github.com/hamzawahab/bonjou-cli/internal/config"
	"github.com/hamzawahab/bonjou-cli/internal/events"
	"github.com/hamzawahab/bonjou-cli/internal/history"
	"github.com/hamzawahab/bonjou-cli/internal/logger"
)

const (
	kindMessage = "message"
	kindFile    = "file"
	kindFolder  = "folder"
	kindAck     = "ack"
	ackTimeout  = 12 * time.Second
)

var errServiceStopping = errors.New("transfer service stopping")

type envelope struct {
	Kind       string `json:"kind"`
	TransferID string `json:"transfer_id,omitempty"`
	From       string `json:"from"`
	FromIP     string `json:"from_ip"`
	To         string `json:"to"`
	Name       string `json:"name"`
	Size       int64  `json:"size"`
	Timestamp  int64  `json:"ts"`
	Message    string `json:"message"`
	Checksum   string `json:"checksum"`
	HMAC       string `json:"hmac"`
	Encrypted  bool   `json:"encrypted,omitempty"`
	Nonce      string `json:"nonce,omitempty"`
	Encoding   string `json:"encoding,omitempty"`
	AckKind    string `json:"ack_kind,omitempty"`
	AckStatus  string `json:"ack_status,omitempty"`
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
}

func (t *TransferService) isStopping() bool {
	select {
	case <-t.stop:
		return true
	default:
		return false
	}
}

func NewTransferService(cfg *config.Config, logger *logger.Logger, history *history.Manager, events chan<- events.Event, discovery *DiscoveryService) *TransferService {
	return &TransferService{
		cfg:          cfg,
		logger:       logger,
		history:      history,
		events:       events,
		discovery:    discovery,
		stop:         make(chan struct{}),
		chunkSize:    cfg.ChunkSizeBytes(),
		chunkTimeout: cfg.ChunkTimeout(),
		pendingAcks:  make(map[string]chan *envelope),
	}
}

func (t *TransferService) Start(username, ip string) error {
	addr := fmt.Sprintf(":%d", t.cfg.ListenPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		// Provide helpful error message for port conflicts
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
			t.listener.Close()
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
	err = t.verifyEnvelope(env, key)
	if err != nil {
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
		t.emit(events.Event{Type: events.MessageReceived, Title: "Message", Message: env.Message, From: env.From, Timestamp: time.Now()})
		_ = t.history.AppendChat(env.From, env.To, env.Message)
	case kindFile:
		return t.receiveFile(conn, env, key)
	case kindFolder:
		return t.receiveFolder(conn, env, key)
	case kindAck:
		return t.receiveDeliveryAck(env)
	default:
		return fmt.Errorf("unknown payload kind: %s", env.Kind)
	}
	return nil
}

// SendMessage delivers plain text to a peer.
func (t *TransferService) SendMessage(peer *Peer, message string) error {
	if t.isStopping() {
		return errServiceStopping
	}
	localUser, localIP := t.identity()
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
	return t.history.AppendChat(localUser, peer.Username, message)
}

// SendFile streams a file to the peer.
func (t *TransferService) SendFile(peer *Peer, path string) (err error) {
	if t.isStopping() {
		return errServiceStopping
	}
	localUser, localIP := t.identity()
	name := filepath.Base(path)
	defer func() {
		if err != nil {
			t.emitTransferIssue(kindFile, name, peer.Username, path, err)
		}
	}()
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("file not found: %s", filepath.Base(path))
		}
		return fmt.Errorf("cannot access file: %v", err)
	}
	if info.IsDir() {
		return errors.New("path is a directory — use @folder to send a folder")
	}
	// Open the file once to atomically derive its size, checksum, and the
	// byte stream that will be sent.  This prevents the race where the
	// file could be modified between a separate stat/checksum call and
	// the subsequent stream, which would cause a checksum mismatch on the
	// receiver side even though the send itself looked successful.
	tf, err := openTransferFile(path)
	if err != nil {
		return fmt.Errorf("cannot read file for transfer: %v", err)
	}
	defer tf.file.Close()
	env := &envelope{
		Kind:       kindFile,
		TransferID: newTransferID(),
		From:       localUser,
		FromIP:     localIP,
		To:         peer.Username,
		Name:       name,
		Size:       tf.size,
		Timestamp:  time.Now().Unix(),
		Checksum:   tf.checksum,
	}
	stream := func(writer io.Writer, enc cipher.Stream) error {
		ctx := progressContext{
			id:        fmt.Sprintf("file:%s", env.Name),
			label:     fmt.Sprintf("Sending %s", env.Name),
			path:      path,
			peer:      formatPeer(peer),
			direction: "send",
			kind:      kindFile,
		}
		return t.copyWithProgress(writer, enc, tf.file, tf.size, ctx)
	}
	if err = t.sendEnvelope(peer, env, stream); err != nil {
		return err
	}
	return t.history.AppendTransfer(localUser, peer.Username, path, env.Size, kindFile)
}

// SendFolder compresses and shares a folder with the peer.
func (t *TransferService) SendFolder(peer *Peer, dir string) (err error) {
	if t.isStopping() {
		return errServiceStopping
	}
	localUser, localIP := t.identity()
	displayName := filepath.Base(dir)
	defer func() {
		if err != nil {
			t.emitTransferIssue(kindFolder, displayName, peer.Username, dir, err)
		}
	}()
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("folder not found: %s", filepath.Base(dir))
		}
		return fmt.Errorf("cannot access folder: %v", err)
	}
	if !info.IsDir() {
		return errors.New("path is not a directory — use @file to send a single file")
	}
	archivePath, err := zipDirectory(dir)
	if err != nil {
		return err
	}
	defer os.Remove(archivePath)
	// Open the archive once to atomically derive its size, checksum, and
	// the byte stream to send — same race-elimination rationale as SendFile.
	tf, err := openTransferFile(archivePath)
	if err != nil {
		return fmt.Errorf("cannot read compressed archive for transfer: %v", err)
	}
	defer tf.file.Close()
	env := &envelope{
		Kind:       kindFolder,
		TransferID: newTransferID(),
		From:       localUser,
		FromIP:     localIP,
		To:         peer.Username,
		Name:       displayName + ".zip",
		Size:       tf.size,
		Timestamp:  time.Now().Unix(),
		Checksum:   tf.checksum,
	}
	stream := func(writer io.Writer, enc cipher.Stream) error {
		ctx := progressContext{
			id:        fmt.Sprintf("folder:%s", displayName),
			label:     fmt.Sprintf("Sending %s", displayName),
			path:      dir,
			peer:      formatPeer(peer),
			direction: "send",
			kind:      kindFolder,
		}
		return t.copyWithProgress(writer, enc, tf.file, tf.size, ctx)
	}
	if err = t.sendEnvelope(peer, env, stream); err != nil {
		return err
	}
	return t.history.AppendTransfer(localUser, peer.Username, dir, env.Size, kindFolder)
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
	if writer != nil {
		if t.isStopping() {
			return errServiceStopping
		}
		var ackKey string
		var ackCh chan *envelope
		if env.Kind == kindFile || env.Kind == kindFolder {
			ackKey = deliveryAckKey(env.TransferID, env.Kind, transferDisplayName(env.Kind, env.Name), peerLabelOrIP(peer))
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
	}
	return nil
}

func (t *TransferService) signEnvelope(env *envelope, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(env.Kind))
	mac.Write([]byte(env.TransferID))
	mac.Write([]byte(env.From))
	mac.Write([]byte(env.FromIP))
	mac.Write([]byte(env.To))
	mac.Write([]byte(env.Message))
	mac.Write([]byte(env.Name))
	mac.Write([]byte(env.Checksum))
	sizeBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(sizeBuf, uint64(env.Size))
	mac.Write(sizeBuf)
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
	destPath := uniquePath(filepath.Join(t.cfg.ReceivedFilesDir, env.Name))

	// Security: Prevent path traversal attacks
	absDestPath, err := filepath.Abs(destPath)
	if err != nil {
		return fmt.Errorf("invalid path: %v", err)
	}
	absDirPath, err := filepath.Abs(t.cfg.ReceivedFilesDir)
	if err != nil {
		return fmt.Errorf("invalid destination directory: %v", err)
	}
	if !strings.HasPrefix(absDestPath, absDirPath) {
		return fmt.Errorf("path traversal not allowed: file would be written outside received directory")
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
		file.Close()
		if cleanup {
			_ = os.Remove(destPath)
		}
	}()
	hasher := sha256.New()
	progressID := fmt.Sprintf("recv:%s", env.Name)
	label := fmt.Sprintf("Receiving %s", env.Name)
	ctx := progressContext{
		id:        progressID,
		label:     label,
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
		t.emitTransferIssue(kindFile, env.Name, env.From, destPath, err)
		return err
	}
	receivedChecksum := hex.EncodeToString(hasher.Sum(nil))
	if !strings.EqualFold(receivedChecksum, env.Checksum) {
		if err := t.writeInlineDeliveryAck(conn, key, env, kindFile, env.Name, "error"); err != nil {
			t.sendDeliveryAckOutOfBand(env, kindFile, env.Name, "error")
		}
		msg := fmt.Sprintf("File '%s' from %s did not arrive intact — data was corrupted in transit. Please ask them to send it again.", env.Name, env.From)
		t.emit(events.Event{Type: events.Error, Title: "Transfer integrity check failed", Message: msg, From: env.From, Timestamp: time.Now(), Path: destPath})
		return fmt.Errorf("transfer integrity check failed for '%s'", env.Name)
	}
	cleanup = false
	if err := t.writeInlineDeliveryAck(conn, key, env, kindFile, env.Name, "ok"); err != nil {
		t.sendDeliveryAckOutOfBand(env, kindFile, env.Name, "ok")
	}
	savedName := filepath.Base(destPath)
	displayMsg := env.Name
	if savedName != env.Name {
		displayMsg = fmt.Sprintf("%s (saved as '%s' — a file with this name already existed)", env.Name, savedName)
	}
	t.emit(events.Event{Type: events.FileReceived, Title: "File received", Message: displayMsg, From: env.From, Path: destPath, Size: env.Size, Timestamp: time.Now()})
	localUser, _ := t.identity()
	return t.history.AppendTransfer(env.From, localUser, destPath, env.Size, kindFile)
}

func (t *TransferService) receiveFolder(conn net.Conn, env *envelope, key []byte) error {
	if t.isStopping() {
		return errServiceStopping
	}
	tempPath := uniquePath(filepath.Join(os.TempDir(), env.Name))
	file, err := os.Create(tempPath)
	if err != nil {
		return err
	}
	defer func() {
		file.Close()
		os.Remove(tempPath)
	}()
	hasher := sha256.New()
	progressID := fmt.Sprintf("recv:%s", env.Name)
	destDirName := strings.TrimSuffix(env.Name, ".zip")
	displayPath := filepath.Join(t.cfg.ReceivedFoldersDir, destDirName)
	ctx := progressContext{
		id:        progressID,
		label:     fmt.Sprintf("Receiving %s", destDirName),
		path:      displayPath,
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
		t.emitTransferIssue(kindFolder, destDirName, env.From, displayPath, err)
		return err
	}
	receivedChecksum := hex.EncodeToString(hasher.Sum(nil))
	if !strings.EqualFold(receivedChecksum, env.Checksum) {
		if err := t.writeInlineDeliveryAck(conn, key, env, kindFolder, strings.TrimSuffix(env.Name, ".zip"), "error"); err != nil {
			t.sendDeliveryAckOutOfBand(env, kindFolder, strings.TrimSuffix(env.Name, ".zip"), "error")
		}
		msg := fmt.Sprintf("Folder '%s' from %s did not arrive intact — data was corrupted in transit. Please ask them to send it again.", destDirName, env.From)
		t.emit(events.Event{Type: events.Error, Title: "Transfer integrity check failed", Message: msg, From: env.From, Timestamp: time.Now(), Path: tempPath})
		return fmt.Errorf("transfer integrity check failed for folder '%s'", destDirName)
	}
	destDir := uniquePath(displayPath)

	// Security: Prevent path traversal attacks
	absDestDir, err := filepath.Abs(destDir)
	if err != nil {
		return fmt.Errorf("invalid path: %v", err)
	}
	absFolderPath, err := filepath.Abs(t.cfg.ReceivedFoldersDir)
	if err != nil {
		return fmt.Errorf("invalid destination directory: %v", err)
	}
	if !strings.HasPrefix(absDestDir, absFolderPath) {
		return fmt.Errorf("path traversal not allowed: folder would be written outside received directory")
	}

	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return err
	}
	if err := unzip(tempPath, destDir); err != nil {
		_ = os.RemoveAll(destDir) // Clean up partially extracted folder on failure
		if ackErr := t.writeInlineDeliveryAck(conn, key, env, kindFolder, destDirName, "error"); ackErr != nil {
			t.sendDeliveryAckOutOfBand(env, kindFolder, destDirName, "error")
		}
		return err
	}
	if err := t.writeInlineDeliveryAck(conn, key, env, kindFolder, destDirName, "ok"); err != nil {
		t.sendDeliveryAckOutOfBand(env, kindFolder, destDirName, "ok")
	}
	savedDirName := filepath.Base(destDir)
	displayFolderMsg := destDirName
	if savedDirName != destDirName {
		displayFolderMsg = fmt.Sprintf("%s (saved as '%s' — a folder with this name already existed)", destDirName, savedDirName)
	}
	t.emit(events.Event{Type: events.FolderReceived, Title: "Folder received", Message: displayFolderMsg, From: env.From, Path: destDir, Size: env.Size, Timestamp: time.Now()})
	localUser, _ := t.identity()
	return t.history.AppendTransfer(env.From, localUser, destDir, env.Size, kindFolder)
}

func (t *TransferService) copyWithProgress(writer io.Writer, enc cipher.Stream, reader io.Reader, total int64, ctx progressContext) error {
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
		Kind:       kindAck,
		TransferID: source.TransferID,
		From:       localUser,
		FromIP:     localIP,
		To:         source.From,
		Name:       name,
		Timestamp:  time.Now().Unix(),
		AckKind:    kind,
		AckStatus:  status,
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
		t.emit(events.Event{
			Type:      events.Status,
			Title:     "Delivery confirmed",
			Message:   fmt.Sprintf("Delivered: %s '%s' to %s", kindLabel, name, peer),
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
		Kind:       kindAck,
		TransferID: source.TransferID,
		From:       localUser,
		FromIP:     localIP,
		To:         source.From,
		Name:       transferDisplayName(kind, name),
		Timestamp:  time.Now().Unix(),
		AckKind:    kind,
		AckStatus:  status,
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

func deliveryAckKey(transferID, kind, name, peer string) string {
	if trimmedID := strings.ToLower(strings.TrimSpace(transferID)); trimmedID != "" {
		return trimmedID
	}
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
	if _, ok := t.pendingAcks[key]; ok {
		delete(t.pendingAcks, key)
	}
	t.pendingAckMu.Unlock()
}

func (t *TransferService) notifyPendingAck(env *envelope) {
	peer := strings.TrimSpace(env.From)
	if peer == "" {
		peer = strings.TrimSpace(env.FromIP)
	}
	key := deliveryAckKey(env.TransferID, env.AckKind, transferDisplayName(env.AckKind, env.Name), peer)
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
	case kindFolder:
		return "Folder"
	case kindFile:
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
	if strings.EqualFold(strings.TrimSpace(kind), kindFolder) {
		return strings.TrimSuffix(trimmed, ".zip")
	}
	return trimmed
}

// humanizeTransferError converts low-level network and OS error strings
// into plain-language messages that make sense to a non-technical user.
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
	case strings.Contains(msg, "no delivery confirmation"):
		return "receiver did not confirm the transfer in time — ask them if they received the approval request, then try again"
	case strings.Contains(msg, "unexpected EOF") || strings.EqualFold(strings.TrimSpace(msg), "EOF"):
		return "connection closed before transfer confirmation — please try again"
	case strings.Contains(msg, "broken pipe") || strings.Contains(msg, "use of closed network connection"):
		return "connection was lost mid-transfer — please try again"
	case strings.Contains(msg, "reset by peer"):
		return "peer closed the connection unexpectedly — please try again"
	case strings.Contains(msg, "no such file") || strings.Contains(msg, "file not found"):
		return "file no longer exists at the specified path"
	case strings.Contains(msg, "permission denied"):
		return "permission denied — check file and folder permissions"
	case strings.Contains(msg, "contains a symbolic link"):
		return msg
	case strings.Contains(msg, "contains an unsupported special file"):
		return msg
	case strings.Contains(msg, "no delivery confirmation"),
		strings.Contains(msg, "integrity check failed"),
		strings.Contains(msg, "Delivery failed"):
		return msg // already a plain-language message
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
	if errors.Is(err, errServiceStopping) {
		t.emit(events.Event{
			Type:      events.Status,
			Title:     "Transfer cancelled",
			Message:   fmt.Sprintf("%s '%s' to %s was cancelled (Bonjou is shutting down)", transferKindLabel(kind), label, who),
			From:      who,
			Path:      path,
			Timestamp: time.Now(),
		})
		return
	}
	reason := humanizeTransferError(err)
	t.emit(events.Event{
		Type:      events.Error,
		Title:     "Transfer failed",
		Message:   fmt.Sprintf("Failed to send %s '%s' to %s: %s", transferKindLabel(kind), label, who, reason),
		From:      who,
		Path:      path,
		Timestamp: time.Now(),
	})
}

func randomNonce() ([]byte, error) {
	nonce := make([]byte, aes.BlockSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

func newTransferID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("tx-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}

func deriveCipherKey(shared []byte) []byte {
	h := sha256.New()
	h.Write([]byte("bonjou-encryption"))
	h.Write(shared)
	return h.Sum(nil)
}

func newCipherStream(shared []byte, nonce []byte) (cipher.Stream, error) {
	if len(nonce) != aes.BlockSize {
		return nil, fmt.Errorf("invalid nonce length")
	}
	key := deriveCipherKey(shared)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCTR(block, nonce), nil
}

func encryptText(shared []byte, nonce []byte, plaintext string) (string, error) {
	stream, err := newCipherStream(shared, nonce)
	if err != nil {
		return "", err
	}
	plainBytes := []byte(plaintext)
	cipherBytes := make([]byte, len(plainBytes))
	stream.XORKeyStream(cipherBytes, plainBytes)
	return base64.StdEncoding.EncodeToString(cipherBytes), nil
}

func decryptText(shared []byte, nonce []byte, ciphertext, encoding string) (string, error) {
	if encoding != "" && encoding != "base64" {
		return "", fmt.Errorf("unsupported encoding: %s", encoding)
	}
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	stream, err := newCipherStream(shared, nonce)
	if err != nil {
		return "", err
	}
	plain := make([]byte, len(data))
	stream.XORKeyStream(plain, data)
	return string(plain), nil
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

func (t *TransferService) sharedKey(peerPublicKey string) ([]byte, error) {
	if strings.TrimSpace(peerPublicKey) == "" {
		return nil, errors.New("missing peer public key")
	}
	key, err := sharedKeyFromPeerPublic(t.cfg.Secret, peerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("derive shared key from peer public key: %w", err)
	}
	return key, nil
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
	length := binary.BigEndian.Uint32(header)
	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}
	return payload, nil
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
	var publicKey string
	for _, ip := range remoteIPs {
		if key, ok := t.discovery.SharedPublicKey("", ip); ok && strings.TrimSpace(key) != "" {
			publicKey = key
			break
		}
	}
	if strings.TrimSpace(publicKey) == "" {
		return nil, nil, fmt.Errorf("peer key unavailable for %s", remoteIPs[0])
	}
	shared, err := t.sharedKey(publicKey)
	if err != nil {
		return nil, nil, err
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
	cipherText := make([]byte, len(plain))
	stream.XORKeyStream(cipherText, plain)
	mac := hmac.New(sha256.New, shared)
	mac.Write([]byte("bonjou-envelope-v1"))
	mac.Write(nonce)
	mac.Write(cipherText)
	sealed := sealedEnvelope{
		Nonce:    hex.EncodeToString(nonce),
		Payload:  base64.StdEncoding.EncodeToString(cipherText),
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
	cipherText, err := base64.StdEncoding.DecodeString(sealed.Payload)
	if err != nil {
		return nil, fmt.Errorf("decode envelope payload: %w", err)
	}
	providedMAC, err := hex.DecodeString(sealed.HMAC)
	if err != nil {
		return nil, fmt.Errorf("decode envelope hmac: %w", err)
	}
	mac := hmac.New(sha256.New, shared)
	mac.Write([]byte("bonjou-envelope-v1"))
	mac.Write(nonce)
	mac.Write(cipherText)
	if !hmac.Equal(mac.Sum(nil), providedMAC) {
		return nil, errors.New("invalid envelope signature")
	}
	stream, err := newCipherStream(shared, nonce)
	if err != nil {
		return nil, err
	}
	plain := make([]byte, len(cipherText))
	stream.XORKeyStream(plain, cipherText)
	var env envelope
	if err := json.Unmarshal(plain, &env); err != nil {
		return nil, err
	}
	return &env, nil
}

func remoteIPCandidates(conn net.Conn) []string {
	if conn == nil || conn.RemoteAddr() == nil {
		return nil
	}
	raw := strings.TrimSpace(conn.RemoteAddr().String())
	host, _, err := net.SplitHostPort(raw)
	if err == nil {
		raw = strings.TrimSpace(host)
	}
	if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
		raw = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(raw, "["), "]"))
	}
	if strings.Contains(raw, "%") {
		raw = strings.TrimSpace(strings.SplitN(raw, "%", 2)[0])
	}
	if raw == "" {
		return nil
	}
	seen := make(map[string]struct{})
	add := func(value string, out *[]string) {
		v := strings.TrimSpace(value)
		if v == "" {
			return
		}
		if _, exists := seen[v]; exists {
			return
		}
		seen[v] = struct{}{}
		*out = append(*out, v)
	}
	var out []string
	add(raw, &out)
	if ip := net.ParseIP(raw); ip != nil {
		add(ip.String(), &out)
		if v4 := ip.To4(); v4 != nil {
			add(v4.String(), &out)
			add("::ffff:"+v4.String(), &out)
		}
	}
	return out
}

func formatPeer(peer *Peer) string {
	if peer == nil {
		return ""
	}
	if peer.Username != "" {
		return fmt.Sprintf("%s@%s:%d", peer.Username, peer.IP, peer.Port)
	}
	if peer.IP != "" && peer.Port != 0 {
		return fmt.Sprintf("%s:%d", peer.IP, peer.Port)
	}
	return peer.IP
}

func formatRemote(name, ip string) string {
	trimmedName := strings.TrimSpace(name)
	trimmedIP := strings.TrimSpace(ip)
	switch {
	case trimmedName != "" && trimmedIP != "":
		return fmt.Sprintf("%s@%s", trimmedName, trimmedIP)
	case trimmedIP != "":
		return trimmedIP
	default:
		return trimmedName
	}
}

// transferFile holds an open file handle together with its pre-computed
// size and SHA-256 checksum. Because all three values come from a single
// open(2) call, the stat/checksum/stream race — which can cause a
// checksum mismatch when a file is modified between separate operations —
// is eliminated.
type transferFile struct {
	file     *os.File
	size     int64
	checksum string
}

// openTransferFile opens path once, reads through it to compute its
// SHA-256 checksum, then seeks back to the beginning so the caller can
// stream the exact same bytes to the network.
func openTransferFile(path string) (*transferFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	stat, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		f.Close()
		return nil, fmt.Errorf("failed to read file for checksum: %w", err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return nil, fmt.Errorf("failed to seek file for streaming: %w", err)
	}
	return &transferFile{
		file:     f,
		size:     stat.Size(),
		checksum: hex.EncodeToString(hasher.Sum(nil)),
	}, nil
}

func uniquePath(path string) string {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return path
	}
	base := path
	ext := ""
	if dot := strings.LastIndex(path, "."); dot != -1 {
		base = path[:dot]
		ext = path[dot:]
	}
	for i := 1; ; i++ {
		candidate := fmt.Sprintf("%s_%d%s", base, i, ext)
		if _, err := os.Stat(candidate); errors.Is(err, os.ErrNotExist) {
			return candidate
		}
	}
}

func zipDirectory(dir string) (string, error) {
	tempFile, err := os.CreateTemp("", "bonjou-*.zip")
	if err != nil {
		return "", err
	}
	defer tempFile.Close()
	archive := zip.NewWriter(tempFile)
	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			targetInfo, statErr := os.Stat(path)
			if statErr == nil && targetInfo.IsDir() {
				return fmt.Errorf("folder contains a symbolic link to a directory that Bonjou cannot package safely: %s", path)
			}
			return fmt.Errorf("folder contains a symbolic link that Bonjou cannot package safely: %s", path)
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		if info.IsDir() {
			if rel == "." {
				return nil
			}
			_, err := archive.Create(rel + "/")
			return err
		}
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		header.Name = rel
		header.Method = zip.Deflate
		writer, err := archive.CreateHeader(header)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("folder contains an unsupported special file: %s", path)
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		if _, err := io.Copy(writer, file); err != nil {
			file.Close()
			return err
		}
		return file.Close()
	})
	if err != nil {
		archive.Close()
		return "", err
	}
	if err := archive.Close(); err != nil {
		return "", err
	}
	return tempFile.Name(), nil
}

func unzip(zipPath, dest string) error {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer reader.Close()
	for _, file := range reader.File {
		targetPath := filepath.Join(dest, file.Name)
		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(targetPath, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
			return err
		}
		src, err := file.Open()
		if err != nil {
			return err
		}
		dst, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, file.Mode())
		if err != nil {
			src.Close()
			return err
		}
		if _, err := io.Copy(dst, src); err != nil {
			src.Close()
			dst.Close()
			return err
		}
		src.Close()
		if err := dst.Close(); err != nil {
			return err
		}
	}
	return nil
}
