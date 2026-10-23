package accounts

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/komari-monitor/komari/cmd/flags"
	"github.com/komari-monitor/komari/database/dbcore"
	"github.com/pquerna/otp/totp"
)

func TestMain(m *testing.M) {
	flags.DatabaseType = "sqlite"
	flags.DatabaseFile = "file:komari_accounts_2fa_test?mode=memory&cache=shared"
	_ = dbcore.GetDBInstance()
	os.Exit(m.Run())
}

func newTestUser(t *testing.T) string {
	t.Helper()
	user, err := CreateAccount("2fa-user-"+uuid.NewString(), "test-password")
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	t.Cleanup(func() {
		_ = DeleteAccountByUsername(user.Username)
	})
	return user.UUID
}

func TestPendingTwoFactorExpires(t *testing.T) {
	previous := pendingTwoFactorTTL
	pendingTwoFactorTTL = time.Millisecond
	t.Cleanup(func() { pendingTwoFactorTTL = previous })

	userUUID := newTestUser(t)
	secret, _, err := Begin2FaEnrollment(userUUID)
	if err != nil {
		t.Fatalf("begin enrollment: %v", err)
	}
	time.Sleep(10 * time.Millisecond)

	if _, ok := Pending2FASecret(userUUID); ok {
		t.Fatal("expired pending secret is still usable")
	}
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	if err := Complete2FAEnrollment(userUUID, code, ""); !errors.Is(err, ErrNoPendingTwoFactor) {
		t.Fatalf("Complete2FAEnrollment error = %v, want ErrNoPendingTwoFactor", err)
	}
	if current, _ := Get2FaSecret(userUUID); current != "" {
		t.Fatal("expired enrollment modified the stored secret")
	}
}

func TestPendingTwoFactorIsBoundToUser(t *testing.T) {
	userA := newTestUser(t)
	userB := newTestUser(t)

	secretA, _, err := Begin2FaEnrollment(userA)
	if err != nil {
		t.Fatalf("begin enrollment: %v", err)
	}
	if _, ok := Pending2FASecret(userB); ok {
		t.Fatal("user B sees user A's pending secret")
	}
	codeA, err := totp.GenerateCode(secretA, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	// User B must not be able to complete an enrollment with A's code.
	if err := Complete2FAEnrollment(userB, codeA, ""); !errors.Is(err, ErrNoPendingTwoFactor) {
		t.Fatalf("user B enrollment error = %v, want ErrNoPendingTwoFactor", err)
	}
	if current, _ := Get2FaSecret(userB); current != "" {
		t.Fatal("user B enrollment changed its stored secret")
	}
	if current, _ := Get2FaSecret(userA); current != "" {
		t.Fatal("user A enrollment was completed by user B's request")
	}
}

func TestEnable2FaIsConditionalOnCurrentState(t *testing.T) {
	userUUID := newTestUser(t)
	if err := Enable2Fa(userUUID, "", "SECRET-1"); err != nil {
		t.Fatalf("first enable: %v", err)
	}

	// A plain enable must not overwrite an existing secret.
	if err := Enable2Fa(userUUID, "", "SECRET-2"); !errors.Is(err, ErrTwoFactorStateChanged) {
		t.Fatalf("overwrite error = %v, want ErrTwoFactorStateChanged", err)
	}
	if current, _ := Get2FaSecret(userUUID); current != "SECRET-1" {
		t.Fatalf("stored secret = %q after rejected overwrite", current)
	}

	// Replacing with the expected current secret succeeds.
	if err := Enable2Fa(userUUID, "SECRET-1", "SECRET-2"); err != nil {
		t.Fatalf("replace: %v", err)
	}
	if current, _ := Get2FaSecret(userUUID); current != "SECRET-2" {
		t.Fatalf("stored secret = %q after replacement", current)
	}
}

func TestComplete2FAEnrollmentRequiresCurrentCodeWhenEnabled(t *testing.T) {
	userUUID := newTestUser(t)
	if err := Enable2Fa(userUUID, "", "EXISTING"); err != nil {
		t.Fatalf("enable: %v", err)
	}
	pending, _, err := Begin2FaEnrollment(userUUID)
	if err != nil {
		t.Fatalf("begin enrollment: %v", err)
	}
	newCode, err := totp.GenerateCode(pending, time.Now())
	if err != nil {
		t.Fatalf("generate new code: %v", err)
	}

	if err := Complete2FAEnrollment(userUUID, newCode, ""); !errors.Is(err, ErrCurrentTwoFactorRequired) {
		t.Fatalf("error = %v, want ErrCurrentTwoFactorRequired", err)
	}
	if current, _ := Get2FaSecret(userUUID); current != "EXISTING" {
		t.Fatalf("stored secret = %q after rejected replacement", current)
	}

	if err := Complete2FAEnrollment(userUUID, newCode, "000000"); !errors.Is(err, ErrCurrentTwoFactorInvalid) {
		t.Fatalf("error = %v, want ErrCurrentTwoFactorInvalid", err)
	}
	if current, _ := Get2FaSecret(userUUID); current != "EXISTING" {
		t.Fatalf("stored secret = %q after invalid current code", current)
	}
}
