package nxs

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/df-mc/go-nxs/admission"
)

const stateVersion = 1

// state is the durable state of an instance. It contains secrets and must only be
// readable by its owner.
type state struct {
	Version    int    `json:"version"`
	Provider   string `json:"provider"`
	PrivateKey string `json:"privateKey"`
	// PendingPrivateKey is a replacement machine key whose rotation may not have completed.
	PendingPrivateKey string `json:"pendingPrivateKey,omitempty"`

	Registration *registration `json:"registration,omitempty"`
	// Challenge is an enrollment challenge whose completion may have been lost.
	Challenge *challenge `json:"challenge,omitempty"`

	Generation int64 `json:"generation"`
	Sequence   int64 `json:"sequence"`

	TicketKeys   []ticketKey `json:"ticketKeys,omitempty"`
	KeyRequestID string      `json:"keyRequestId,omitempty"`

	PendingEvents []event `json:"pendingEvents,omitempty"`
}

// keys returns the installed admission keys, with the active one last.
func (s *state) keys() []admission.Key {
	keys := make([]admission.Key, 0, len(s.TicketKeys))
	for _, k := range s.TicketKeys {
		key := admission.Key{ID: k.KeyID, Secret: k.Secret}
		if k.NotBefore > 0 {
			key.NotBefore = time.UnixMilli(k.NotBefore)
		}
		if k.RetireAfter > 0 {
			key.RetireAfter = time.UnixMilli(k.RetireAfter)
		}
		keys = append(keys, key)
	}
	return keys
}

// store persists state in a locked directory.
type store struct {
	dir    string
	unlock func() error
}

func openStore(dir string) (*store, error) {
	if dir == "" {
		return nil, errors.New("nxs: StateDir must be set")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("nxs: create state directory: %w", err)
	}
	unlock, err := lockDir(dir)
	if err != nil {
		return nil, fmt.Errorf("nxs: lock state directory %s (is another instance using it?): %w", dir, err)
	}
	return &store{dir: dir, unlock: unlock}, nil
}

func (s *store) path() string { return filepath.Join(s.dir, "state.json") }

func (s *store) load() (*state, error) {
	b, err := os.ReadFile(s.path())
	if errors.Is(err, os.ErrNotExist) {
		return &state{Version: stateVersion}, nil
	} else if err != nil {
		return nil, fmt.Errorf("nxs: read state: %w", err)
	}
	st := &state{}
	if err := json.Unmarshal(b, st); err != nil {
		return nil, fmt.Errorf("nxs: decode state: %w", err)
	}
	if st.Version != stateVersion {
		return nil, fmt.Errorf("nxs: unsupported state version %d", st.Version)
	}
	return st, nil
}

// save atomically replaces the state file.
func (s *store) save(st *state) error {
	b, err := json.MarshalIndent(st, "", "\t")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.dir, "state-*.tmp")
	if err != nil {
		return fmt.Errorf("nxs: save state: %w", err)
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil && !errors.Is(err, errors.ErrUnsupported) {
		_ = tmp.Close()
		return fmt.Errorf("nxs: save state: %w", err)
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("nxs: save state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("nxs: save state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("nxs: save state: %w", err)
	}
	if err := os.Rename(tmp.Name(), s.path()); err != nil {
		return fmt.Errorf("nxs: save state: %w", err)
	}
	return syncDir(s.dir)
}

func (s *store) close() error { return s.unlock() }
