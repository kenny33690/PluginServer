package plugin

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

type Registry struct {
	db *sql.DB
}

func OpenRegistry(ctx context.Context, dsn string) (*Registry, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	registry := &Registry{db: db}
	if err := registry.init(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}

	return registry, nil
}

func (r *Registry) Close() error {
	if r == nil || r.db == nil {
		return nil
	}
	return r.db.Close()
}

func (r *Registry) init(ctx context.Context) error {
	const stmt = `
CREATE TABLE IF NOT EXISTS PluginRegistry (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT NOT NULL,
	cert_string TEXT NOT NULL,
	subject TEXT NOT NULL,
	not_before TIMESTAMP NOT NULL,
	not_after TIMESTAMP NOT NULL,
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`

	if _, err := r.db.ExecContext(ctx, stmt); err != nil {
		return fmt.Errorf("create PluginRegistry: %w", err)
	}

	return nil
}

func (r *Registry) SavePlugin(ctx context.Context, name string, certString string, subject string, notBefore time.Time, notAfter time.Time) error {
	const stmt = `
INSERT INTO PluginRegistry (name, cert_string, subject, not_before, not_after)
VALUES (?, ?, ?, ?, ?);
`

	if _, err := r.db.ExecContext(ctx, stmt, name, certString, subject, notBefore.UTC(), notAfter.UTC()); err != nil {
		return fmt.Errorf("insert PluginRegistry: %w", err)
	}

	return nil
}
