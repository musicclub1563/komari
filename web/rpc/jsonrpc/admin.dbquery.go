package jsonrpc

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/komari-monitor/komari/database/auditlog"
	"github.com/komari-monitor/komari/database/dbcore"
	"github.com/komari-monitor/komari/internal/metricstore"
	"github.com/komari-monitor/komari/pkg/metric"
	"github.com/komari-monitor/komari/pkg/rpc"
)

const (
	databaseTargetMain    = "main"
	databaseTargetMetrics = "metrics"
	defaultDBQueryLimit   = 1000
	maxDBQueryLimit       = 10000
)

type databaseQueryParams struct {
	Database *string `json:"database"`
	SQL      string  `json:"sql"`
	Args     []any   `json:"args"`
	Limit    *int    `json:"limit"`
}

type databaseExecParams struct {
	Database *string `json:"database"`
	SQL      string  `json:"sql"`
	Args     []any   `json:"args"`
}

type databaseTablesParams struct {
	Database *string `json:"database"`
}

type databaseQueryResponse struct {
	Database  string   `json:"database"`
	Driver    string   `json:"driver"`
	Columns   []string `json:"columns"`
	Rows      [][]any  `json:"rows"`
	RowCount  int      `json:"row_count"`
	Truncated bool     `json:"truncated"`
}

type databaseExecResponse struct {
	Database     string `json:"database"`
	Driver       string `json:"driver"`
	RowsAffected int64  `json:"rows_affected"`
	LastInsertID *int64 `json:"last_insert_id"`
}

type databaseTablesResponse struct {
	Database string   `json:"database"`
	Driver   string   `json:"driver"`
	Tables   []string `json:"tables"`
}

func init() {
	// 原始 SQL 属于系统级能力：插件即使获批 allowSystemRPC 也不能调用。
	rpc.MarkPluginForbidden("admin:dbQuery")
	rpc.MarkPluginForbidden("admin:dbExec")
	RegisterWithGroupAndMeta("dbQuery", rpc.RoleAdmin, adminDBQuery, &rpc.MethodMeta{
		Name:    "admin:dbQuery",
		Summary: "Execute a SQL query against the main or metrics database",
		Params: []rpc.ParamMeta{
			{Name: "database", Type: "main | metrics", Description: "Database target (default main)"},
			{Name: "sql", Type: "string", Required: true, Description: "SQL query to execute"},
			{Name: "args", Type: "any[]", Description: "Positional SQL parameters"},
			{Name: "limit", Type: "number", Description: "Maximum rows to return (default 1000, max 10000)"},
		},
		Returns: "{ database: string, driver: string, columns: string[], rows: any[][], row_count: number, truncated: boolean }",
	})
	RegisterWithGroupAndMeta("dbExec", rpc.RoleAdmin, adminDBExec, &rpc.MethodMeta{
		Name:    "admin:dbExec",
		Summary: "Execute a SQL statement against the main or metrics database",
		Params: []rpc.ParamMeta{
			{Name: "database", Type: "main | metrics", Description: "Database target (default main)"},
			{Name: "sql", Type: "string", Required: true, Description: "SQL statement to execute"},
			{Name: "args", Type: "any[]", Description: "Positional SQL parameters"},
		},
		Returns: "{ database: string, driver: string, rows_affected: number, last_insert_id: number | null }",
	})
	RegisterWithGroupAndMeta("dbTables", rpc.RoleAdmin, adminDBTables, &rpc.MethodMeta{
		Name:    "admin:dbTables",
		Summary: "List tables in the main or metrics database",
		Params: []rpc.ParamMeta{
			{Name: "database", Type: "main | metrics", Description: "Database target (default main)"},
		},
		Returns: "{ database: string, driver: string, tables: string[] }",
	})
}

func adminDBQuery(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	params, target, statement, limit, rpcErr := parseDatabaseQueryParams(req)
	if rpcErr != nil {
		return nil, rpcErr
	}
	// 查询入口只读：否则它可以绕过 dbExec 的写入语义与审计，直接修改数据。
	if err := ensureReadOnlyStatement(statement); err != nil {
		return nil, rpc.MakeError(rpc.InvalidParams, err.Error(), nil)
	}

	actor, ip := auditActor(ctx)
	auditlog.Log(ip, actor, "query database SQL on "+target+": "+sqlAuditSummary(statement), "info")

	response, err := queryDatabase(ctx, target, statement, params.Args, limit)
	if err != nil {
		return nil, rpc.MakeError(rpc.InternalError, "Failed to execute database query: "+err.Error(), nil)
	}
	return response, nil
}

func adminDBExec(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var params databaseExecParams
	if err := req.BindParams(&params); err != nil {
		return nil, rpc.MakeError(rpc.InvalidParams, "Invalid request body: "+err.Error(), nil)
	}
	target, rpcErr := parseDatabaseTarget(params.Database)
	if rpcErr != nil {
		return nil, rpcErr
	}
	statement := strings.TrimSpace(params.SQL)
	if statement == "" {
		return nil, rpc.MakeError(rpc.InvalidParams, "sql is required", nil)
	}

	actor, ip := auditActor(ctx)
	auditlog.Log(ip, actor, "execute database SQL on "+target+": "+sqlAuditSummary(statement), "warn")

	result, driver, err := executeDatabase(ctx, target, statement, params.Args)
	if err != nil {
		return nil, rpc.MakeError(rpc.InternalError, "Failed to execute database statement: "+err.Error(), nil)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return nil, rpc.MakeError(rpc.InternalError, "Failed to read affected row count: "+err.Error(), nil)
	}

	var lastInsertID *int64
	if id, err := result.LastInsertId(); err == nil {
		lastInsertID = &id
	}
	return databaseExecResponse{
		Database:     target,
		Driver:       string(driver),
		RowsAffected: rowsAffected,
		LastInsertID: lastInsertID,
	}, nil
}

func adminDBTables(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var params databaseTablesParams
	if err := req.BindParams(&params); err != nil {
		return nil, rpc.MakeError(rpc.InvalidParams, "Invalid request body: "+err.Error(), nil)
	}
	target, rpcErr := parseDatabaseTarget(params.Database)
	if rpcErr != nil {
		return nil, rpcErr
	}

	response, err := listDatabaseTables(ctx, target)
	if err != nil {
		return nil, rpc.MakeError(rpc.InternalError, "Failed to list database tables: "+err.Error(), nil)
	}
	return response, nil
}

// readOnlyStatementPrefixes 是 dbQuery 允许的首个关键字。WITH 与 PRAGMA 刻意
// 不在其中：CTE 可以以 DELETE/UPDATE 结尾，部分 PRAGMA 会写入数据库。
var readOnlyStatementPrefixes = map[string]struct{}{
	"SELECT":   {},
	"EXPLAIN":  {},
	"SHOW":     {},
	"DESCRIBE": {},
	"DESC":     {},
}

// writeStatementKeywords 只要作为独立词元出现就拒绝。它们大多是 SQL 保留字，
// 正常只读查询不会命中，覆盖：EXPLAIN 后面的写入语句（PostgreSQL 的 EXPLAIN
// ANALYZE 会真正执行语句）、SELECT ... INTO / OUTFILE / DUMPFILE、SQLite 的
// load_extension、MySQL 的 LOAD_FILE，以及 PostgreSQL 的运维函数。
// REPLACE 刻意不在其中：它是常用字符串函数，而 REPLACE INTO 会被首个关键字
// 检查拦下。
var writeStatementKeywords = map[string]struct{}{
	"INSERT": {}, "UPDATE": {}, "DELETE": {}, "MERGE": {},
	"CREATE": {}, "ALTER": {}, "DROP": {}, "TRUNCATE": {}, "RENAME": {},
	"GRANT": {}, "REVOKE": {},
	"INTO": {}, "OUTFILE": {}, "DUMPFILE": {},
	"ATTACH": {}, "DETACH": {}, "PRAGMA": {}, "VACUUM": {}, "REINDEX": {},
	"LOCK": {},
	"LOAD_FILE": {}, "LOAD_EXTENSION": {},
	"PG_TERMINATE_BACKEND": {}, "PG_CANCEL_BACKEND": {},
	"PG_RELOAD_CONF": {}, "PG_ROTATE_LOGFILE": {},
	"PG_SWITCH_WAL": {}, "PG_CREATE_RESTORE_POINT": {},
}

// ensureReadOnlyStatement rejects statements that can modify data or files
// through the query endpoint. It is a conservative lexical check, not a SQL
// parser: comments, string literals and quoted identifiers are removed first,
// the remaining text is tokenised, and anything not recognisable as a read-only
// query is refused. Statements are also limited to one, because a second
// statement turns a query into an arbitrary write.
//
// Residual risk is documented rather than hidden: a read-only SELECT can still
// call database functions with side effects (user-defined functions,
// pg_sleep), and the check may reject unusual but harmless syntax. The real
// boundary is the admin role plus the plugin call guard.
func ensureReadOnlyStatement(statement string) error {
	code, err := rewriteSQL(statement, "''", false)
	if err != nil {
		return err
	}
	if strings.TrimSpace(code) == "" {
		return fmt.Errorf("sql is required")
	}
	// 结尾的空语句分隔符无害，中间出现分号则是多语句。
	if body := strings.TrimRight(strings.TrimSpace(code), ";\r\n\t "); strings.Contains(body, ";") {
		return fmt.Errorf("dbQuery accepts a single statement")
	}
	tokens := sqlTokens(code)
	if len(tokens) == 0 {
		return fmt.Errorf("sql is required")
	}
	if _, ok := readOnlyStatementPrefixes[tokens[0]]; !ok {
		return fmt.Errorf("dbQuery accepts read-only statements only (SELECT/EXPLAIN/SHOW/DESCRIBE); use dbExec for writes")
	}
	// PostgreSQL/MySQL 8 的 EXPLAIN ANALYZE 会执行被解释的语句。
	if tokens[0] == "EXPLAIN" && containsSQLToken(tokens, "ANALYZE") {
		return fmt.Errorf("dbQuery does not allow EXPLAIN ANALYZE: it executes the statement")
	}
	// SHOW CREATE TABLE/VIEW/... 是只读的：CREATE 是 SHOW 的子命令。
	showCreate := tokens[0] == "SHOW" && len(tokens) > 1 && tokens[1] == "CREATE"
	for index, token := range tokens {
		if showCreate && index == 1 {
			continue
		}
		if _, blocked := writeStatementKeywords[token]; blocked {
			return fmt.Errorf("dbQuery does not allow the %s keyword; only read-only queries are permitted", token)
		}
	}
	return nil
}

func containsSQLToken(tokens []string, name string) bool {
	for _, token := range tokens {
		if token == name {
			return true
		}
	}
	return false
}

// sqlTokens splits sanitized SQL into upper-case word tokens.
func sqlTokens(code string) []string {
	tokens := make([]string, 0, 16)
	for index := 0; index < len(code); {
		if !isSQLWordByte(code[index]) {
			index++
			continue
		}
		start := index
		for index < len(code) && isSQLWordByte(code[index]) {
			index++
		}
		tokens = append(tokens, strings.ToUpper(code[start:index]))
	}
	return tokens
}

func isSQLWordByte(b byte) bool {
	return b == '_' || (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

// rewriteSQL returns a copy of statement with ordinary comments removed and the
// content of string literals, quoted identifiers and PostgreSQL dollar-quoted
// strings replaced by literalPlaceholder. When redactNumbers is set, numeric
// literals become "?" as well.
//
// Backslash escapes are deliberately not honoured: MySQL interprets them and
// standard SQL does not, and ending a literal early only makes the keyword
// check stricter. MySQL executable comments ("/*! ... */") keep their content,
// because the server executes what is inside them.
func rewriteSQL(statement, literalPlaceholder string, redactNumbers bool) (string, error) {
	var out strings.Builder
	out.Grow(len(statement) + 8)
	executableEnd := -1
	for index := 0; index < len(statement); {
		if executableEnd >= 0 && index >= executableEnd {
			index += 2 // closing */ of an executable comment
			executableEnd = -1
			continue
		}
		c := statement[index]
		switch {
		case c == '-' && strings.HasPrefix(statement[index:], "--"):
			index = skipSQLLine(statement, index)
			out.WriteByte(' ')
		case c == '/' && strings.HasPrefix(statement[index:], "/*"):
			start := index + 2
			executable := start < len(statement) && statement[start] == '!'
			if executable {
				start++
			}
			end := strings.Index(statement[start:], "*/")
			if end < 0 {
				return "", fmt.Errorf("unterminated SQL comment")
			}
			if executable {
				out.WriteByte(' ')
				executableEnd = start + end
				index = start
				continue
			}
			index = start + end + 2
			out.WriteByte(' ')
		case c == '\'' || c == '"' || c == '`':
			next, err := skipSQLLiteral(statement, index)
			if err != nil {
				return "", err
			}
			out.WriteString(literalPlaceholder)
			index = next
		case c == '$':
			next, quoted, err := skipSQLDollarQuoted(statement, index)
			if err != nil {
				return "", err
			}
			if !quoted {
				out.WriteByte(c)
				index++
				continue
			}
			out.WriteString(literalPlaceholder)
			index = next
		case redactNumbers && c >= '0' && c <= '9' && (index == 0 || !isSQLWordByte(statement[index-1])):
			index = skipSQLNumber(statement, index)
			out.WriteByte('?')
		default:
			out.WriteByte(c)
			index++
		}
	}
	return out.String(), nil
}

func skipSQLLine(statement string, index int) int {
	for index < len(statement) && statement[index] != '\n' {
		index++
	}
	return index
}

func skipSQLLiteral(statement string, index int) (int, error) {
	quote := statement[index]
	index++
	for index < len(statement) {
		if statement[index] != quote {
			index++
			continue
		}
		// A doubled quote is an escaped quote, not the end of the literal.
		if index+1 < len(statement) && statement[index+1] == quote {
			index += 2
			continue
		}
		return index + 1, nil
	}
	return 0, fmt.Errorf("unterminated quoted text in SQL")
}

// skipSQLDollarQuoted skips a PostgreSQL dollar-quoted string such as $$...$$ or
// $tag$...$tag$. Standalone "$" characters (MySQL identifiers, placeholders)
// are reported as not quoted so the caller can keep scanning normally.
func skipSQLDollarQuoted(statement string, index int) (int, bool, error) {
	tagEnd := index + 1
	for tagEnd < len(statement) && statement[tagEnd] != '$' {
		b := statement[tagEnd]
		if !(b == '_' || (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')) {
			return 0, false, nil
		}
		tagEnd++
	}
	if tagEnd >= len(statement) {
		return 0, false, nil
	}
	tag := statement[index : tagEnd+1]
	offset := strings.Index(statement[tagEnd+1:], tag)
	if offset < 0 {
		return 0, false, fmt.Errorf("unterminated dollar-quoted string in SQL")
	}
	return tagEnd + 1 + offset + len(tag), true, nil
}

func skipSQLNumber(statement string, index int) int {
	for index < len(statement) {
		c := statement[index]
		switch {
		case (c >= '0' && c <= '9') || c == '.' || c == '_':
			index++
		case c == 'e' || c == 'E':
			next := index + 1
			if next < len(statement) && (statement[next] == '+' || statement[next] == '-') {
				next++
			}
			if next < len(statement) && statement[next] >= '0' && statement[next] <= '9' {
				index = next
				continue
			}
			return index
		default:
			return index
		}
	}
	return index
}

// sqlAuditSummary renders a bounded, redacted one-line summary for the audit
// log: comments are dropped, literal values (including numbers) become "?", and
// the result is truncated. Bound parameters and result rows are never part of
// the summary, so credentials and query results cannot leak into the log.
func sqlAuditSummary(statement string) string {
	const limit = 160
	redacted, err := rewriteSQL(statement, "?", true)
	if err != nil {
		return "(unparsable statement)"
	}
	normalized := strings.Join(strings.Fields(redacted), " ")
	if normalized == "" {
		return "(empty statement)"
	}
	if len(normalized) > limit {
		return normalized[:limit] + "…"
	}
	return normalized
}

func parseDatabaseQueryParams(req *rpc.JsonRpcRequest) (databaseQueryParams, string, string, int, *rpc.JsonRpcError) {
	var params databaseQueryParams
	if err := req.BindParams(&params); err != nil {
		return databaseQueryParams{}, "", "", 0, rpc.MakeError(rpc.InvalidParams, "Invalid request body: "+err.Error(), nil)
	}
	target, rpcErr := parseDatabaseTarget(params.Database)
	if rpcErr != nil {
		return databaseQueryParams{}, "", "", 0, rpcErr
	}
	statement := strings.TrimSpace(params.SQL)
	if statement == "" {
		return databaseQueryParams{}, "", "", 0, rpc.MakeError(rpc.InvalidParams, "sql is required", nil)
	}
	limit := defaultDBQueryLimit
	if params.Limit != nil {
		limit = *params.Limit
		if limit < 1 || limit > maxDBQueryLimit {
			return databaseQueryParams{}, "", "", 0, rpc.MakeError(rpc.InvalidParams, fmt.Sprintf("limit must be between 1 and %d", maxDBQueryLimit), nil)
		}
	}
	return params, target, statement, limit, nil
}

func parseDatabaseTarget(value *string) (string, *rpc.JsonRpcError) {
	if value == nil {
		return databaseTargetMain, nil
	}
	target := strings.TrimSpace(*value)
	if target != databaseTargetMain && target != databaseTargetMetrics {
		return "", rpc.MakeError(rpc.InvalidParams, "database must be main or metrics", nil)
	}
	return target, nil
}

func queryDatabase(ctx context.Context, target, statement string, args []any, limit int) (databaseQueryResponse, error) {
	rows, driver, release, err := openDatabaseRows(ctx, target, statement, args...)
	if err != nil {
		return databaseQueryResponse{}, err
	}
	defer func() {
		_ = rows.Close()
		release()
	}()

	columns, resultRows, truncated, err := collectDatabaseRows(rows, limit)
	if err != nil {
		return databaseQueryResponse{}, err
	}
	return databaseQueryResponse{
		Database:  target,
		Driver:    string(driver),
		Columns:   columns,
		Rows:      resultRows,
		RowCount:  len(resultRows),
		Truncated: truncated,
	}, nil
}

func executeDatabase(ctx context.Context, target, statement string, args []any) (sql.Result, metric.Driver, error) {
	switch target {
	case databaseTargetMain:
		db, err := dbcore.GetDBInstance().DB()
		if err != nil {
			return nil, "", err
		}
		result, err := db.ExecContext(ctx, statement, args...)
		return result, metric.DriverSQLite, err
	case databaseTargetMetrics:
		return metricstore.ExecContext(ctx, statement, args...)
	default:
		return nil, "", fmt.Errorf("unsupported database target: %s", target)
	}
}

func listDatabaseTables(ctx context.Context, target string) (databaseTablesResponse, error) {
	var (
		rows         *sql.Rows
		actualDriver metric.Driver
		release      func()
		err          error
	)
	switch target {
	case databaseTargetMain:
		statement, err := tableListSQL(metric.DriverSQLite)
		if err != nil {
			return databaseTablesResponse{}, err
		}
		rows, actualDriver, release, err = openDatabaseRows(ctx, target, statement)
	case databaseTargetMetrics:
		rows, actualDriver, release, err = metricstore.QueryForDriver(ctx, tableListSQL)
	default:
		return databaseTablesResponse{}, fmt.Errorf("unsupported database target: %s", target)
	}
	if err != nil {
		return databaseTablesResponse{}, err
	}
	defer func() {
		_ = rows.Close()
		release()
	}()

	tables := make([]string, 0)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return databaseTablesResponse{}, err
		}
		tables = append(tables, name)
	}
	if err := rows.Err(); err != nil {
		return databaseTablesResponse{}, err
	}
	sort.Strings(tables)
	return databaseTablesResponse{Database: target, Driver: string(actualDriver), Tables: tables}, nil
}

func openDatabaseRows(ctx context.Context, target, statement string, args ...any) (*sql.Rows, metric.Driver, func(), error) {
	switch target {
	case databaseTargetMain:
		db, err := dbcore.GetDBInstance().DB()
		if err != nil {
			return nil, "", nil, err
		}
		rows, err := db.QueryContext(ctx, statement, args...)
		return rows, metric.DriverSQLite, func() {}, err
	case databaseTargetMetrics:
		return metricstore.QueryContext(ctx, statement, args...)
	default:
		return nil, "", nil, fmt.Errorf("unsupported database target: %s", target)
	}
}

func collectDatabaseRows(rows *sql.Rows, limit int) ([]string, [][]any, bool, error) {
	columns, err := rows.Columns()
	if err != nil {
		return nil, nil, false, err
	}
	resultRows := make([][]any, 0, limit)
	values := make([]any, len(columns))
	scans := make([]any, len(columns))
	for i := range scans {
		scans[i] = &values[i]
	}

	for rows.Next() {
		if len(resultRows) == limit {
			return columns, resultRows, true, nil
		}
		if err := rows.Scan(scans...); err != nil {
			return nil, nil, false, err
		}
		row := make([]any, len(values))
		for i, value := range values {
			row[i] = normalizeDatabaseValue(value)
		}
		resultRows = append(resultRows, row)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, false, err
	}
	return columns, resultRows, false, nil
}

func normalizeDatabaseValue(value any) any {
	switch value := value.(type) {
	case []byte:
		return string(value)
	case time.Time:
		return value.Format(time.RFC3339Nano)
	default:
		return value
	}
}

func tableListSQL(driver metric.Driver) (string, error) {
	switch driver {
	case metric.DriverSQLite:
		return "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'", nil
	case metric.DriverMySQL:
		return "SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE'", nil
	case metric.DriverPostgreSQL:
		return "SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname = current_schema()", nil
	default:
		return "", fmt.Errorf("unsupported database driver: %s", driver)
	}
}
