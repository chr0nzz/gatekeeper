package queries

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
)

// Backup represents a stored database backup record.
type Backup struct {
	ID        string
	Name      string
	Size      int64
	Storage   string
	CreatedAt int64
}

// BackupStore handles backup metadata CRUD.
type BackupStore struct {
	db *sql.DB
}

// NewBackupStore creates a BackupStore.
func NewBackupStore(db *sql.DB) *BackupStore {
	return &BackupStore{db: db}
}

// List returns all backups ordered newest first.
func (s *BackupStore) List(ctx context.Context) ([]Backup, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, size, storage, created_at FROM backups ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Backup
	for rows.Next() {
		var b Backup
		if err := rows.Scan(&b.ID, &b.Name, &b.Size, &b.Storage, &b.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

// Create inserts a new backup record and returns its ID.
func (s *BackupStore) Create(ctx context.Context, name, storage string, size int64, createdAt int64) (string, error) {
	id := uuid.New().String()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO backups (id, name, size, storage, created_at) VALUES (?, ?, ?, ?, ?)`,
		id, name, size, storage, createdAt,
	)
	return id, err
}

// Delete removes a backup record by ID.
func (s *BackupStore) Delete(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM backups WHERE id=?`, id)
	return err
}

// GetByID returns a single backup record.
func (s *BackupStore) GetByID(ctx context.Context, id string) (*Backup, error) {
	var b Backup
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, size, storage, created_at FROM backups WHERE id=?`, id,
	).Scan(&b.ID, &b.Name, &b.Size, &b.Storage, &b.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &b, err
}

// PruneOldest deletes the oldest backups keeping only the most recent n records for the given storage type.
func (s *BackupStore) PruneOldest(ctx context.Context, storage string, keep int) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name FROM backups WHERE storage=? ORDER BY created_at DESC LIMIT -1 OFFSET ?`,
		storage, keep,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids, names []string
	for rows.Next() {
		var id, name string
		rows.Scan(&id, &name)
		ids = append(ids, id)
		names = append(names, name)
	}
	for _, id := range ids {
		s.db.ExecContext(ctx, `DELETE FROM backups WHERE id=?`, id)
	}
	return names, nil
}
