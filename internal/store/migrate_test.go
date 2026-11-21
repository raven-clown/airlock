package store

import (
	"regexp"
	"strings"
	"testing"
)

var (
	removal       = regexp.MustCompile(`(?i)\b(DROP|RENAME)\b|\bALTER\s+COLUMN\b`)
	addColumn     = regexp.MustCompile(`(?i)\bADD\s+COLUMN\b`)
	notNull       = regexp.MustCompile(`(?i)\bNOT\s+NULL\b`)
	columnDefault = regexp.MustCompile(`(?i)\bDEFAULT\b`)
)

// Two airlock versions run on one schema during a rolling update, so a migration after the
// first only adds, unless it says why it removes something.
func TestMigrationsExpandOnly(t *testing.T) {
	for _, engine := range []string{sqliteDialect.name, postgresDialect.name} {
		ms, err := loadMigrations(engine)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range ms[1:] {
			contract := strings.Contains(m.sql, "-- contract:")
			for _, stmt := range strings.Split(m.sql, ";") {
				switch {
				case removal.MatchString(stmt) && !contract:
					t.Errorf("%s migration %d removes or renames without a -- contract: line: %s", engine, m.version, strings.TrimSpace(stmt))
				case addColumn.MatchString(stmt) && notNull.MatchString(stmt) && !columnDefault.MatchString(stmt):
					t.Errorf("%s migration %d adds a NOT NULL column with no default: %s", engine, m.version, strings.TrimSpace(stmt))
				}
			}
		}
	}
}

func TestMigrationsMatchAcrossEngines(t *testing.T) {
	lite, _ := loadMigrations(sqliteDialect.name)
	pg, _ := loadMigrations(postgresDialect.name)
	if len(lite) != len(pg) {
		t.Fatalf("sqlite has %d migrations, postgres %d", len(lite), len(pg))
	}
	for i := range lite {
		if lite[i].version != pg[i].version {
			t.Fatalf("migration %d: versions %d and %d", i, lite[i].version, pg[i].version)
		}
	}
}
