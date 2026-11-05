package store

import "context"

func (s *Store) ExecForTest(ctx context.Context, query string) error {
	_, err := s.db.ExecContext(ctx, query)
	return err
}

func (s *Store) QueryStringForTest(ctx context.Context, query string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, query).Scan(&v)
	return v, err
}
