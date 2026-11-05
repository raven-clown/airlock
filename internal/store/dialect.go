package store

import (
	"strconv"
	"strings"
)

type dialect struct {
	name     string
	driver   string
	numbered bool
}

var (
	sqliteDialect   = dialect{name: "sqlite", driver: "sqlite"}
	postgresDialect = dialect{name: "postgres", driver: "pgx", numbered: true}
)

// rebind turns ? placeholders into $1, $2 for Postgres. Queries are written once with ?.
func (d dialect) rebind(q string) string {
	if !d.numbered {
		return q
	}
	var b strings.Builder
	n := 0
	quoted := false
	for _, r := range q {
		switch {
		case r == '\'':
			quoted = !quoted
		case r == '?' && !quoted:
			n++
			b.WriteString("$" + strconv.Itoa(n))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
