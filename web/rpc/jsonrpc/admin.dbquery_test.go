package jsonrpc

import (
	"context"
	"strings"
	"testing"

	"github.com/komari-monitor/komari/pkg/rpc"
)

func TestEnsureReadOnlyStatementAcceptsQueries(t *testing.T) {
	for _, statement := range []string{
		"SELECT 1",
		"  select name from users  ",
		"select count(*) from client_metrics;",
		"EXPLAIN SELECT 1",
		"SHOW TABLES",
		"DESCRIBE users",
		"(SELECT 1)",
		// 注释、字符串字面量里的关键字不影响判定。
		"/* leading comment */ SELECT 1",
		"-- leading comment\nSELECT 1",
		"SELECT 'a;b' AS label",
		"SELECT * FROM logs WHERE message = 'DELETE FROM users'",
		"SELECT REPLACE(name, 'a', 'b') FROM users",
		// SHOW CREATE ... 是只读的。
		"SHOW CREATE TABLE users",
		// PostgreSQL dollar quoting。
		"SELECT $$; DROP TABLE users$$",
	} {
		if err := ensureReadOnlyStatement(statement); err != nil {
			t.Fatalf("read-only statement %q was rejected: %v", statement, err)
		}
	}
}

func TestEnsureReadOnlyStatementRejectsWrites(t *testing.T) {
	cases := map[string]string{
		"update":          "UPDATE users SET password = 'x'",
		"lowercase":       "delete from users where id = 1",
		"insert":          "INSERT INTO users (name) VALUES ('x')",
		"delete":          "DELETE FROM users",
		"drop":            "DROP TABLE users",
		"alter":           "ALTER TABLE users ADD COLUMN x INT",
		"attach":          "ATTACH DATABASE 'x.db' AS x",
		"pragma":          "PRAGMA journal_mode = WAL",
		"cte write":       "WITH x AS (SELECT 1) DELETE FROM users",
		"cte select":      "WITH x AS (SELECT 1) SELECT * FROM x",
		"multi":           "SELECT 1; DROP TABLE users",
		"multi trailing":  "SELECT 1;;DROP TABLE users",
		"select into":     "SELECT * INTO backup_users FROM users",
		"outfile":         "SELECT * FROM users INTO OUTFILE '/tmp/x'",
		"dumpfile":        "SELECT * FROM users INTO DUMPFILE '/tmp/x'",
		"comment prefix":  "-- SELECT 1\nDELETE FROM users",
		"comment between": "SELECT 1 /* c */ ; DROP TABLE users",
		"block comment":   "/* x */ DROP TABLE users",
		"explain analyze": "EXPLAIN ANALYZE DELETE FROM users",
		"explain write":   "EXPLAIN UPDATE users SET name = 'x'",
		"for update":      "SELECT * FROM users WHERE id = 1 FOR UPDATE",
		"load extension":  "SELECT load_extension('evil')",
		"load file":       "SELECT LOAD_FILE('/etc/passwd')",
		"terminate":       "SELECT pg_terminate_backend(123)",
		"executable cmt":  "SELECT 1 /*! , (DELETE FROM users) */",
		"unterminated":    "SELECT 'unterminated",
		"empty":           "   ",
	}
	for name, statement := range cases {
		if err := ensureReadOnlyStatement(statement); err == nil {
			t.Fatalf("%s: statement %q was accepted as read-only", name, statement)
		}
	}
}

func TestDatabaseQueryMethodsAreForbiddenForPlugins(t *testing.T) {
	for _, method := range []string{"admin:dbQuery", "admin:dbExec"} {
		if !rpc.IsPluginForbidden(method) {
			t.Fatalf("%s is callable from plugins", method)
		}
	}
}

// TestDatabaseMethodsHaveNoAlias covers the "alias" half of the guard: the
// registry resolves methods by exact name only, so the plugin guard on
// "admin:dbQuery"/"admin:dbExec" cannot be sidestepped by another spelling, and
// no second registration exposes the same handlers.
func TestDatabaseMethodsHaveNoAlias(t *testing.T) {
	for _, method := range rpc.ListMethods() {
		lower := strings.ToLower(method)
		if !strings.Contains(lower, "dbquery") && !strings.Contains(lower, "dbexec") {
			continue
		}
		if method != "admin:dbQuery" && method != "admin:dbExec" {
			t.Fatalf("unexpected database method %q", method)
		}
	}
	for _, alias := range []string{"dbQuery", "dbquery", "admin:dbquery", "common:dbQuery", "admin:dbQuery "} {
		if resp := rpc.Call(1, alias, nil); resp.Error == nil {
			t.Fatalf("alias %q resolved to a registered method", alias)
		}
	}
	if role := rpc.RequiredRole("admin:dbQuery"); role != rpc.RoleAdmin {
		t.Fatalf("admin:dbQuery requires %q", role)
	}
}

// TestPluginCannotShadowCoreMethod documents the other half: a plugin
// registering a method cannot take over an existing name, so it cannot replace
// the guarded handler with one that is allowed to reach the database.
func TestPluginCannotShadowCoreMethod(t *testing.T) {
	err := rpc.Register("admin:dbQuery", func(_ context.Context, _ *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
		return nil, nil
	})
	if err == nil {
		t.Fatal("duplicate registration of admin:dbQuery was accepted")
	}
}

func TestSQLAuditSummaryRedactsValues(t *testing.T) {
	const secret = "hunter2"
	summary := sqlAuditSummary("UPDATE users SET password = '" + secret + "' WHERE id = 42")
	if strings.Contains(summary, secret) {
		t.Fatalf("audit summary leaked a literal value: %q", summary)
	}
	if strings.Contains(summary, "42") {
		t.Fatalf("audit summary leaked a numeric literal: %q", summary)
	}
	if !strings.Contains(summary, "UPDATE users SET password = ?") {
		t.Fatalf("audit summary lost the statement shape: %q", summary)
	}
	// 注释不进日志，空白折叠成一行。
	if got := sqlAuditSummary("SELECT 1 -- secret note"); got != "SELECT ?" {
		t.Fatalf("audit summary = %q", got)
	}
	if got := sqlAuditSummary("  select\n\n  1  "); got != "select ?" {
		t.Fatalf("audit summary = %q", got)
	}
}

func TestSQLAuditSummaryIsBounded(t *testing.T) {
	got := sqlAuditSummary("SELECT col_" + strings.Repeat("x", 500) + " FROM t")
	if len(got) > 170 || !strings.HasSuffix(got, "…") {
		t.Fatalf("long SQL was not truncated: %d bytes", len(got))
	}
}
