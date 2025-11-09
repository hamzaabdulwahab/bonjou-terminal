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
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hamzawahab/bonjou-terminal/internal/config"
	"github.com/hamzawahab/bonjou-terminal/internal/events"
	"github.com/hamzawahab/bonjou-terminal/internal/history"
	"github.com/hamzawahab/bonjou-terminal/internal/logger"
)

const (
	kindMessage = "message"
	kindFile    = "file"
	kindFolder  = "folder"
)

var errServiceStopping = errors.New("transfer service stopping")

type envelope struct {
	Kind      string `json:"kind"`
	From      string `json:"from"`
	FromIP    string `json:"from_ip"`
	To        string `json:"to"`
	Name      string `json:"name"`
	Size      int64  `json:"size"`
	Timestamp int64  `json:"ts"`
	Message   string `json:"message"`
	Checksum  string `json:"checksum"`
	HMAC      string `json:"hmac"`
	Encrypted bool   `json:"encrypted,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
	Encoding  string `json:"encoding,omitempty"`
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
	}
}

func (t *TransferService) Start(username, ip string) error {
	addr := fmt.Sprintf(":%d", t.cfg.ListenPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
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
	env, err := readEnvelope(conn)
	if err != nil {
		return err
	}
	key, err := t.verifyEnvelope(env)
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
func (t *TransferService) SendFile(peer *Peer, path string) error {
	if t.isStopping() {
		return errServiceStopping
	}
	localUser, localIP := t.identity()
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return errors.New("path is a directory; use SendFolder")
	}
	checksum, err := fileChecksum(path)
	if err != nil {
		return err
	}
	env := &envelope{
		Kind:      kindFile,
		From:      localUser,
		FromIP:    localIP,
		To:        peer.Username,
		Name:      filepath.Base(path),
		Size:      info.Size(),
		Timestamp: time.Now().Unix(),
		Checksum:  checksum,
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
		return t.copyWithProgress(writer, enc, path, env.Size, ctx)
	}
	if err := t.sendEnvelope(peer, env, stream); err != nil {
		return err
	}
	t.emit(events.Event{Type: events.FileSent, Title: "File sent", Message: env.Name, To: peer.Username, Path: path, Size: env.Size, Timestamp: time.Now()})
	return t.history.AppendTransfer(localUser, peer.Username, path, env.Size, kindFile)
}

// SendFolder compresses and shares a folder with the peer.
func (t *TransferService) SendFolder(peer *Peer, dir string) error {
	if t.isStopping() {
		return errServiceStopping
	}
	localUser, localIP := t.identity()
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("path is not a directory")
	}
	archivePath, err := zipDirectory(dir)
	if err != nil {
		return err
	}
	defer os.Remove(archivePath)
	archiveInfo, err := os.Stat(archivePath)
	if err != nil {
		return err
	}
	checksum, err := fileChecksum(archivePath)
	if err != nil {
		return err
	}
	displayName := filepath.Base(dir)
	env := &envelope{
		Kind:      kindFolder,
		From:      localUser,
		FromIP:    localIP,
		To:        peer.Username,
		Name:      displayName + ".zip",
		Size:      archiveInfo.Size(),
		Timestamp: time.Now().Unix(),
		Checksum:  checksum,
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
		return t.copyWithProgress(writer, enc, archivePath, env.Size, ctx)
	}
	if err := t.sendEnvelope(peer, env, stream); err != nil {
		return err
	}
	t.emit(events.Event{Type: events.FolderSent, Title: "Folder sent", Message: displayName, To: peer.Username, Path: dir, Size: env.Size, Timestamp: time.Now()})
	return t.history.AppendTransfer(localUser, peer.Username, dir, env.Size, kindFolder)
}

func (t *TransferService) sendEnvelope(peer *Peer, env *envelope, writer func(io.Writer, cipher.Stream) error) error {
	if t.isStopping() {
		return errServiceStopping
	}
	if peer.Secret == "" {
		return errors.New("peer secret unknown; ensure peer was discovered")
	}
	shared := t.sharedKey(peer.Secret)
	var nonceBytes []byte
	if writer != nil || env.Kind == kindMessage {
		var err error
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
	if err := writeEnvelope(conn, env); err != nil {
		return err
	}
	if writer != nil {
		if t.isStopping() {
			return errServiceStopping
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
	}
	return nil
}

func (t *TransferService) signEnvelope(env *envelope, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(env.Kind))
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
	return hex.EncodeToString(mac.Sum(nil))
}

func (t *TransferService) verifyEnvelope(env *envelope) ([]byte, error) {
	secret, ok := t.discovery.SharedSecret(env.From, env.FromIP)
	if !ok || secret == "" {
		return nil, fmt.Errorf("discarded %s from %s (%s): peer not discovered yet", env.Kind, env.From, env.FromIP)
	}
	key := t.sharedKey(secret)
	expected := t.signEnvelope(env, key)
	expectedBytes, err := hex.DecodeString(expected)
	if err != nil {
		return nil, fmt.Errorf("unable to compute signature for %s: %w", env.From, err)
	}
	providedBytes, err := hex.DecodeString(env.HMAC)
	if err != nil {
		return nil, fmt.Errorf("invalid signature data from %s: %w", env.From, err)
	}
	if !hmac.Equal(expectedBytes, providedBytes) {
		return nil, fmt.Errorf("discarded %s from %s (%s): signature mismatch", env.Kind, env.From, env.FromIP)
	}
	return key, nil
}

func (t *TransferService) receiveFile(conn net.Conn, env *envelope, key []byte) error {
	if t.isStopping() {
		return errServiceStopping
	}
	destPath := uniquePath(filepath.Join(t.cfg.ReceivedFilesDir, env.Name))
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
		return err
	}
	receivedChecksum := hex.EncodeToString(hasher.Sum(nil))
	if !strings.EqualFold(receivedChecksum, env.Checksum) {
		t.emit(events.Event{Type: events.Error, Title: "Checksum mismatch", Message: env.Name, From: env.From, Timestamp: time.Now(), Path: destPath})
		return errors.New("checksum mismatch")
	}
	cleanup = false
	t.emit(events.Event{Type: events.FileReceived, Title: "File received", Message: env.Name, From: env.From, Path: destPath, Size: env.Size, Timestamp: time.Now()})
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
		return err
	}
	receivedChecksum := hex.EncodeToString(hasher.Sum(nil))
	if !strings.EqualFold(receivedChecksum, env.Checksum) {
		t.emit(events.Event{Type: events.Error, Title: "Checksum mismatch", Message: destDirName, From: env.From, Timestamp: time.Now(), Path: tempPath})
		return errors.New("checksum mismatch")
	}
	destDir := uniquePath(displayPath)
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return err
	}
	if err := unzip(tempPath, destDir); err != nil {
		return err
	}
	t.emit(events.Event{Type: events.FolderReceived, Title: "Folder received", Message: destDirName, From: env.From, Path: destDir, Size: env.Size, Timestamp: time.Now()})
	localUser, _ := t.identity()
	return t.history.AppendTransfer(env.From, localUser, destDir, env.Size, kindFolder)
}

func (t *TransferService) copyWithProgress(writer io.Writer, enc cipher.Stream, sourcePath string, total int64, ctx progressContext) error {
	file, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer file.Close()
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
		n, err := file.Read(buf)
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

func (t *TransferService) emit(evt events.Event) {
	select {
	case t.events <- evt:
	default:
	}
}

func randomNonce() ([]byte, error) {
	nonce := make([]byte, aes.BlockSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return nonce, nil
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

func (t *TransferService) sharedKey(peerSecret string) []byte {
	parts := []string{t.cfg.Secret, peerSecret}
	sort.Strings(parts)
	sum := sha256.Sum256([]byte(parts[0] + ":" + parts[1]))
	return sum[:]
}

func writeEnvelope(conn net.Conn, env *envelope) error {
	data, err := json.Marshal(env)
	if err != nil {
		return err
	}
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

func readEnvelope(conn net.Conn) (*envelope, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(header)
	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}
	var env envelope
	if err := json.Unmarshal(payload, &env); err != nil {
		return nil, err
	}
	return &env, nil
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

func fileChecksum(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
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
