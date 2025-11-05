package network

import (
	"archive/zip"
	"crypto/hmac"
	"crypto/sha256"
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
}

// TransferService manages TCP message and payload transfers.
type TransferService struct {
	cfg       *config.Config
	logger    *logger.Logger
	history   *history.Manager
	events    chan<- events.Event
	listener  net.Listener
	stop      chan struct{}
	stopOnce  sync.Once
	wait      sync.WaitGroup
	localUser string
	localIP   string
}

func NewTransferService(cfg *config.Config, logger *logger.Logger, history *history.Manager, events chan<- events.Event) *TransferService {
	return &TransferService{
		cfg:     cfg,
		logger:  logger,
		history: history,
		events:  events,
		stop:    make(chan struct{}),
	}
}

func (t *TransferService) Start(username, ip string) error {
	addr := fmt.Sprintf(":%d", t.cfg.ListenPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	t.listener = ln
	t.localUser = username
	t.localIP = ip
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
				t.logger.Error("handle connection: %v", err)
			}
		}(conn)
	}
}

func (t *TransferService) handleConnection(conn net.Conn) error {
	env, err := readEnvelope(conn)
	if err != nil {
		return err
	}
	if !t.verifyEnvelope(env) {
		return errors.New("invalid message signature")
	}
	switch env.Kind {
	case kindMessage:
		t.emit(events.Event{Type: events.MessageReceived, Title: "Message", Message: env.Message, From: env.From, Timestamp: time.Now()})
		_ = t.history.AppendChat(env.From, env.To, env.Message)
	case kindFile:
		return t.receiveFile(conn, env)
	case kindFolder:
		return t.receiveFolder(conn, env)
	default:
		return fmt.Errorf("unknown payload kind: %s", env.Kind)
	}
	return nil
}

// SendMessage delivers plain text to a peer.
func (t *TransferService) SendMessage(peer *Peer, message string) error {
	env := &envelope{
		Kind:      kindMessage,
		From:      t.localUser,
		FromIP:    t.localIP,
		To:        peer.Username,
		Message:   message,
		Timestamp: time.Now().Unix(),
	}
	if err := t.sendEnvelope(peer, env, nil); err != nil {
		return err
	}
	t.emit(events.Event{Type: events.MessageSent, Title: "Message sent", Message: message, To: peer.Username, Timestamp: time.Now()})
	return t.history.AppendChat(t.localUser, peer.Username, message)
}

// SendFile streams a file to the peer.
func (t *TransferService) SendFile(peer *Peer, path string) error {
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
		From:      t.localUser,
		FromIP:    t.localIP,
		To:        peer.Username,
		Name:      filepath.Base(path),
		Size:      info.Size(),
		Timestamp: time.Now().Unix(),
		Checksum:  checksum,
	}
	stream := func(writer io.Writer) error {
		id := fmt.Sprintf("file:%s", env.Name)
		label := fmt.Sprintf("Sending %s", env.Name)
		return t.copyWithProgress(writer, path, env.Size, id, label)
	}
	if err := t.sendEnvelope(peer, env, stream); err != nil {
		return err
	}
	t.emit(events.Event{Type: events.FileSent, Title: "File sent", Message: env.Name, To: peer.Username, Path: path, Size: env.Size, Timestamp: time.Now()})
	return t.history.AppendTransfer(t.localUser, peer.Username, path, env.Size, kindFile)
}

// SendFolder compresses and shares a folder with the peer.
func (t *TransferService) SendFolder(peer *Peer, dir string) error {
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
	env := &envelope{
		Kind:      kindFolder,
		From:      t.localUser,
		FromIP:    t.localIP,
		To:        peer.Username,
		Name:      filepath.Base(dir) + ".zip",
		Size:      archiveInfo.Size(),
		Timestamp: time.Now().Unix(),
		Checksum:  checksum,
	}
	stream := func(writer io.Writer) error {
		id := fmt.Sprintf("folder:%s", env.Name)
		label := fmt.Sprintf("Sending %s", env.Name)
		return t.copyWithProgress(writer, archivePath, env.Size, id, label)
	}
	if err := t.sendEnvelope(peer, env, stream); err != nil {
		return err
	}
	t.emit(events.Event{Type: events.FolderSent, Title: "Folder sent", Message: env.Name, To: peer.Username, Path: dir, Size: env.Size, Timestamp: time.Now()})
	return t.history.AppendTransfer(t.localUser, peer.Username, dir, env.Size, kindFolder)
}

func (t *TransferService) sendEnvelope(peer *Peer, env *envelope, writer func(io.Writer) error) error {
	env.HMAC = t.signEnvelope(env)
	address := fmt.Sprintf("%s:%d", peer.IP, peer.Port)
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := writeEnvelope(conn, env); err != nil {
		return err
	}
	if writer != nil {
		if err := writer(conn); err != nil {
			return err
		}
	}
	return nil
}

func (t *TransferService) signEnvelope(env *envelope) string {
	mac := hmac.New(sha256.New, []byte(t.cfg.Secret))
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
	return hex.EncodeToString(mac.Sum(nil))
}

func (t *TransferService) verifyEnvelope(env *envelope) bool {
	expected := t.signEnvelope(env)
	expectedBytes, err1 := hex.DecodeString(expected)
	providedBytes, err2 := hex.DecodeString(env.HMAC)
	if err1 != nil || err2 != nil {
		return false
	}
	return hmac.Equal(expectedBytes, providedBytes)
}

func (t *TransferService) receiveFile(conn net.Conn, env *envelope) error {
	destPath := uniquePath(filepath.Join(t.cfg.ReceivedFilesDir, env.Name))
	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return err
	}
	file, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer file.Close()
	hasher := sha256.New()
	progressID := fmt.Sprintf("recv:%s", env.Name)
	label := fmt.Sprintf("Receiving %s", env.Name)
	if err := t.readWithProgress(conn, file, env.Size, hasher, progressID, label); err != nil {
		return err
	}
	receivedChecksum := hex.EncodeToString(hasher.Sum(nil))
	if !strings.EqualFold(receivedChecksum, env.Checksum) {
		t.emit(events.Event{Type: events.Error, Title: "Checksum mismatch", Message: env.Name, From: env.From, Timestamp: time.Now(), Path: destPath})
		return errors.New("checksum mismatch")
	}
	t.emit(events.Event{Type: events.FileReceived, Title: "File received", Message: env.Name, From: env.From, Path: destPath, Size: env.Size, Timestamp: time.Now()})
	return t.history.AppendTransfer(env.From, t.localUser, destPath, env.Size, kindFile)
}

func (t *TransferService) receiveFolder(conn net.Conn, env *envelope) error {
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
	label := fmt.Sprintf("Receiving %s", env.Name)
	if err := t.readWithProgress(conn, file, env.Size, hasher, progressID, label); err != nil {
		return err
	}
	receivedChecksum := hex.EncodeToString(hasher.Sum(nil))
	if !strings.EqualFold(receivedChecksum, env.Checksum) {
		t.emit(events.Event{Type: events.Error, Title: "Checksum mismatch", Message: env.Name, From: env.From, Timestamp: time.Now(), Path: tempPath})
		return errors.New("checksum mismatch")
	}
	destDir := uniquePath(filepath.Join(t.cfg.ReceivedFoldersDir, strings.TrimSuffix(env.Name, ".zip")))
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return err
	}
	if err := unzip(tempPath, destDir); err != nil {
		return err
	}
	t.emit(events.Event{Type: events.FolderReceived, Title: "Folder received", Message: env.Name, From: env.From, Path: destDir, Size: env.Size, Timestamp: time.Now()})
	return t.history.AppendTransfer(env.From, t.localUser, destDir, env.Size, kindFolder)
}

func (t *TransferService) copyWithProgress(writer io.Writer, path string, total int64, id, label string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	buf := make([]byte, 64*1024)
	var sent int64
	for {
		n, err := file.Read(buf)
		if n > 0 {
			if _, err := writer.Write(buf[:n]); err != nil {
				return err
			}
			sent += int64(n)
			t.emit(events.Event{Type: events.Progress, Progress: &events.ProgressState{ID: id, Label: label, Current: sent, Total: total}})
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	t.emit(events.Event{Type: events.Progress, Progress: &events.ProgressState{ID: id, Label: label, Current: total, Total: total, Done: true}})
	return nil
}

func (t *TransferService) readWithProgress(reader io.Reader, writer io.Writer, total int64, hash io.Writer, id, label string) error {
	buf := make([]byte, 64*1024)
	var received int64
	multiWriter := io.MultiWriter(writer, hash)
	for received < total {
		remaining := total - received
		chunk := buf
		if int64(len(chunk)) > remaining {
			chunk = buf[:remaining]
		}
		n, err := io.ReadFull(reader, chunk)
		if err != nil {
			return err
		}
		if _, err := multiWriter.Write(chunk[:n]); err != nil {
			return err
		}
		received += int64(n)
		t.emit(events.Event{Type: events.Progress, Progress: &events.ProgressState{ID: id, Label: label, Current: received, Total: total}})
	}
	t.emit(events.Event{Type: events.Progress, Progress: &events.ProgressState{ID: id, Label: label, Current: total, Total: total, Done: true}})
	return nil
}

func (t *TransferService) emit(evt events.Event) {
	select {
	case t.events <- evt:
	default:
	}
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
