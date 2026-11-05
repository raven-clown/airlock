package store

import "testing"

func TestRebind(t *testing.T) {
	tests := []struct {
		name, in, sqlite, postgres string
	}{
		{"none", "SELECT 1", "SELECT 1", "SELECT 1"},
		{"two", "a = ? AND b = ?", "a = ? AND b = ?", "a = $1 AND b = $2"},
		{"quoted", "a = '?' AND b = ?", "a = '?' AND b = ?", "a = '?' AND b = $1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sqliteDialect.rebind(tt.in); got != tt.sqlite {
				t.Errorf("sqlite = %q, want %q", got, tt.sqlite)
			}
			if got := postgresDialect.rebind(tt.in); got != tt.postgres {
				t.Errorf("postgres = %q, want %q", got, tt.postgres)
			}
		})
	}
}

func TestSQLitePath(t *testing.T) {
	tests := []struct{ dsn, want string }{
		{"file:airlock.db", "airlock.db"},
		{"file:/var/lib/a.db?_pragma=x", "/var/lib/a.db"},
		{"a.db", "a.db"},
		{"file::memory:", ""},
		{":memory:", ""},
		{"file:x?mode=memory", ""},
	}
	for _, tt := range tests {
		if got := sqlitePath(tt.dsn); got != tt.want {
			t.Errorf("sqlitePath(%q) = %q, want %q", tt.dsn, got, tt.want)
		}
	}
}
