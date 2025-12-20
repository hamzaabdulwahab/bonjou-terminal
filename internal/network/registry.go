package network

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

var (
	ErrNameTaken           = errors.New("registry: username already reserved by another client")
	ErrRegistryUnavailable = errors.New("registry: service unavailable")
)

// ReserveName asks the configured registry to reserve a username for this client.
// If the registry URL or username is blank the call is treated as a no-op.
func ReserveName(ctx context.Context, endpoint, username, secret string) error {
	url := strings.TrimSpace(endpoint)
	handle := strings.TrimSpace(username)
	if url == "" || handle == "" {
		return nil
	}

	payload := map[string]string{
		"username": handle,
		"secret":   secret,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("registry request failed: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusNoContent:
		return nil
	case http.StatusConflict:
		return ErrNameTaken
	case http.StatusServiceUnavailable:
		return ErrRegistryUnavailable
	default:
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		if len(data) == 0 {
			return fmt.Errorf("registry responded with %s", resp.Status)
		}
		return fmt.Errorf("registry responded with %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
}

// ReleaseName informs the registry that the username is no longer in use by this client.
func ReleaseName(ctx context.Context, endpoint, username, secret string) error {
	url := strings.TrimSpace(endpoint)
	handle := strings.TrimSpace(username)
	if url == "" || handle == "" {
		return nil
	}

	payload := map[string]string{
		"username": handle,
		"secret":   secret,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("registry release failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if len(data) == 0 {
		return fmt.Errorf("registry responded with %s", resp.Status)
	}
	return fmt.Errorf("registry responded with %s: %s", resp.Status, strings.TrimSpace(string(data)))
}
