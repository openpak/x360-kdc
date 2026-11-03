// Package pgstate is the Postgres-backed state store the x360 services share.
// One schema per service inside the x360 database; the service creates its own
// schema on start. State is kept as named JSON documents (one row per key) so a
// single database backup covers every player-facing record.
package pgstate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MaxConns is the pool size; the box allows 300 connections for every service.
const MaxConns = 2

var schemaRe = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// ErrNoDSN is returned when a service is started without its database URL.
var ErrNoDSN = errors.New("database URL is not set")

// Store is a pool pinned to one schema, with a documents table.
type Store struct {
	pool *pgxpool.Pool
}

// Open connects to dsn, creates schema when missing and the docs table, and
// pins search_path to the schema. An empty dsn is an error: services refuse to
// start without Postgres.
func Open(ctx context.Context, dsn, schema string) (*Store, error) {
	if dsn == "" {
		return nil, ErrNoDSN
	}
	if !schemaRe.MatchString(schema) {
		return nil, fmt.Errorf("pgstate: bad schema name %q", schema)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, errors.New("pgstate: cannot parse database URL")
	}
	cfg.MaxConns = MaxConns
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	// A schema pre-created for a role that has no CREATE on the database is
	// used as is; CREATE SCHEMA IF NOT EXISTS would still demand the privilege.
	var exists bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname=$1)`, schema).Scan(&exists); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pgstate: %w", err)
	}
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS docs (
			key text PRIMARY KEY,
			value jsonb NOT NULL,
			updated_at timestamptz NOT NULL DEFAULT now())`,
	}
	if !exists {
		stmts = append([]string{"CREATE SCHEMA " + schema}, stmts...)
	}
	for _, q := range stmts {
		if _, err := pool.Exec(ctx, q); err != nil {
			pool.Close()
			return nil, fmt.Errorf("pgstate: %w", err)
		}
	}
	return &Store{pool: pool}, nil
}

// Close releases the pool.
func (s *Store) Close() { s.pool.Close() }

// Pool exposes the pool for services that add their own tables.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Load reads document key into v and reports whether it existed.
func (s *Store) Load(ctx context.Context, key string, v any) (bool, error) {
	var b []byte
	err := s.pool.QueryRow(ctx, `SELECT value FROM docs WHERE key=$1`, key).Scan(&b)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal(b, v)
}

// Save writes document key.
func (s *Store) Save(ctx context.Context, key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO docs(key,value) VALUES($1,$2)
		ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=now()`, key, b)
	return err
}
