package network

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Helpers that interact with the local filesystem to support folder
// transfers: build a manifest preview, measure total size, package the
// folder into a temp zip for streaming, and extract a received zip back
// into a destination directory.

// folderPreview produces a textual preview of the folder contents for use
// in the receiver's @view output. Folders sort before files; the listing
// is capped at maxLines entries with an "... and N more" trailer.
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

// zipDirectory writes the directory tree at `dir` into a fresh temp .zip
// file and returns the temp file path. The caller is responsible for
// removing the file when done. The cancel channel allows the user to
// abort mid-zip for very large folders.
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

// directorySize sums the sizes of every file under root for use as the
// pre-compression "actual size" reported in the folder offer envelope.
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

// unzip extracts src into dest, refusing any zip member whose resolved
// path would escape dest (defends against zip-slip attacks).
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
