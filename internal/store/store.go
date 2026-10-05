package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/metadogeunity/solvegio-QuantZen/internal/audit"
)

type Store struct {
	db *sql.DB
}

func New(ctx context.Context, dsn string) (*Store, error) {
	if dsn == "" {
		return &Store{}, nil
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)

	ctx2, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err = db.PingContext(ctx2); err != nil {
		return nil, err
	}

	_, err = db.ExecContext(ctx2, `
		create table if not exists audit_events(
			id text primary key,
			time timestamptz not null,
			method text,
			type text,
			endpoint text,
			tenant text,
			key_id text,
			decision text,
			latency_ms bigint,
			details text,
			prev_hash text,
			hash text
		);
		alter table audit_events add column if not exists method text;
	`)
	if err != nil {
		return nil, fmt.Errorf("schema: %w", err)
	}

	return &Store{db: db}, nil
}

func (s *Store) Insert(ctx context.Context, e audit.Event) error {
	if s == nil || s.db == nil {
		return nil
	}

	_, err := s.db.ExecContext(ctx, `
		insert into audit_events(
			id,time,method,type,endpoint,tenant,key_id,decision,latency_ms,details,prev_hash,hash
		)
		values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		on conflict (id) do nothing
	`,
		e.ID, e.Time, e.Method, e.Type, e.Endpoint, e.Tenant, e.KeyID,
		e.Decision, e.LatencyMs, e.Details, e.PrevHash, e.Hash,
	)
	return err
}

func (s *Store) List(ctx context.Context, limit int) ([]audit.Event, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	if limit <= 0 || limit > 500 {
		limit = 500
	}

	rows, err := s.db.QueryContext(ctx, `
		select id,time,method,type,endpoint,tenant,key_id,decision,latency_ms,details,prev_hash,hash
		from audit_events
		order by time desc
		limit $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	events := make([]audit.Event, 0, limit)
	for rows.Next() {
		var e audit.Event
		if err := rows.Scan(
			&e.ID, &e.Time, &e.Method, &e.Type, &e.Endpoint, &e.Tenant,
			&e.KeyID, &e.Decision, &e.LatencyMs, &e.Details, &e.PrevHash, &e.Hash,
		); err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return events, nil
}
