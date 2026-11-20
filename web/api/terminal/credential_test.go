package terminal

import (
	"testing"
	"time"

	"github.com/komari-monitor/komari/database/dbcore"
	"github.com/komari-monitor/komari/internal/config"
)

func TestTerminalCredentialAPIKeyRotation(t *testing.T) {
	if err := dbcore.Initialize(); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	original, _ := config.GetAs[string](config.ApiKeyKey, "")
	if err := config.Set(config.ApiKeyKey, "key-1"); err != nil {
		t.Fatalf("set api key: %v", err)
	}
	t.Cleanup(func() { _ = config.Set(config.ApiKeyKey, original) })

	credential := &terminalCredential{apiKey: "key-1"}
	if !credential.valid() {
		t.Fatal("credential with matching api key should be valid")
	}

	// 轮换后旧快照必须失效：已建立的终端不能继续沿用旧 Key。
	if err := config.Set(config.ApiKeyKey, "key-2"); err != nil {
		t.Fatalf("rotate api key: %v", err)
	}
	if credential.valid() {
		t.Fatal("credential must be invalid after api key rotation")
	}

	// 清空配置后同样视为撤销。
	if err := config.Set(config.ApiKeyKey, ""); err != nil {
		t.Fatalf("clear api key: %v", err)
	}
	if credential.valid() {
		t.Fatal("credential must be invalid when api key is not configured")
	}
}

func TestTerminalCredentialEmpty(t *testing.T) {
	if (&terminalCredential{}).valid() {
		t.Fatal("empty credential must not be valid")
	}
	var nilCredential *terminalCredential
	if nilCredential.valid() {
		t.Fatal("nil credential must not be valid")
	}
}

func TestTerminalCredentialRecheckInterval(t *testing.T) {
	terminalCredentialRecheckNanos.Store(int64(time.Millisecond))
	t.Cleanup(func() { terminalCredentialRecheckNanos.Store(0) })

	if got := terminalCredentialRecheckInterval(); got != time.Millisecond {
		t.Fatalf("recheck interval = %v, want 1ms", got)
	}
}
