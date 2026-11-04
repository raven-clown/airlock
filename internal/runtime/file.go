package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/raven-clown/airlock/internal/config"
)

// FileSource builds snapshots from a YAML file. An empty path means the built-in defaults.
type FileSource struct {
	path string
	env  config.Env
}

// NewFileSource returns a source reading path.
func NewFileSource(path string, env config.Env) *FileSource {
	return &FileSource{path: path, env: env}
}

// Load implements Source.
func (f *FileSource) Load(context.Context) (*Snapshot, error) {
	if f.path == "" {
		cfg, err := config.Parse(nil, f.env)
		if err != nil {
			return nil, err
		}
		return Build(cfg)
	}
	cfg, err := config.Load(f.path, f.env)
	if err != nil {
		return nil, err
	}
	return Build(cfg)
}

// Version implements Source with a hash of the file, which changes even when a rewrite keeps the mtime.
func (f *FileSource) Version(context.Context) (string, error) {
	if f.path == "" {
		return "default", nil
	}
	data, err := os.ReadFile(filepath.Clean(f.path))
	if err != nil {
		return "", fmt.Errorf("reading config: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
