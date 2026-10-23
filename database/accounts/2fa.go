package accounts

import (
	"errors"
	"image"
	"sync"
	"time"

	"github.com/komari-monitor/komari/database/dbcore"
	"github.com/komari-monitor/komari/database/models"
	"github.com/pquerna/otp/totp"
)

var (
	TwoFactorIssuer = "Komari Monitor"
)

// defaultPendingTwoFactorTTL bounds how long a generated but not yet confirmed
// secret may be used. Enrollments are held server-side so the enable endpoint
// never trusts a secret supplied by the client.
const defaultPendingTwoFactorTTL = 10 * time.Minute

// pendingTwoFactorTTL is a variable so tests can exercise expiry. It is only
// written before any enrollment is created.
var pendingTwoFactorTTL = defaultPendingTwoFactorTTL

type pendingTwoFactor struct {
	secret  string
	expires time.Time
}

var (
	pendingTwoFactorMu sync.Mutex
	pendingTwoFactors  = make(map[string]pendingTwoFactor)
)

var (
	// ErrTwoFactorAlreadyEnabled is returned when an enable attempt would
	// replace an existing secret without proving the current second factor.
	ErrTwoFactorAlreadyEnabled = errors.New("2FA is already enabled; verify the current code to replace it")
	// ErrNoPendingTwoFactor is returned when no unexpired enrollment exists for
	// the user (the secret must come from Generate2FA).
	ErrNoPendingTwoFactor = errors.New("no pending 2FA enrollment; request a new secret first")
	// ErrTwoFactorStateChanged is returned when the stored secret changed
	// between verification and the conditional update.
	ErrTwoFactorStateChanged = errors.New("2FA state changed concurrently; retry the enrollment")
	// ErrCurrentTwoFactorRequired is returned when replacing an enabled secret
	// without providing the current second factor.
	ErrCurrentTwoFactorRequired = errors.New("current 2FA code is required to replace an enabled secret")
	// ErrCurrentTwoFactorInvalid is returned when the current second factor
	// does not match the stored secret.
	ErrCurrentTwoFactorInvalid = errors.New("invalid current 2FA code")
	// ErrInvalidTwoFactorCode is returned when the new code does not match the
	// pending secret.
	ErrInvalidTwoFactorCode = errors.New("invalid 2FA code")
)

func Generate2Fa() (string, image.Image, error) {
	otp, err := totp.Generate(totp.GenerateOpts{
		Issuer:      TwoFactorIssuer,
		AccountName: "komari",
	})
	if err != nil {
		return "", nil, err
	}
	img, err := otp.Image(250, 250)
	if err != nil {
		return "", nil, err
	}
	return otp.Secret(), img, nil
}

// Begin2FaEnrollment generates a secret and binds it to the user for a bounded
// period. The returned secret is only used to render the QR code; the enable
// endpoint reads the server-side copy.
func Begin2FaEnrollment(uuid string) (string, image.Image, error) {
	if uuid == "" {
		return "", nil, errors.New("missing user UUID")
	}
	secret, img, err := Generate2Fa()
	if err != nil {
		return "", nil, err
	}
	pendingTwoFactorMu.Lock()
	pendingTwoFactors[uuid] = pendingTwoFactor{
		secret:  secret,
		expires: time.Now().Add(pendingTwoFactorTTL),
	}
	pendingTwoFactorMu.Unlock()
	return secret, img, nil
}

// Pending2FASecret returns the unexpired pending secret bound to the user.
// It exists so the enable flow (and tests driving real TOTP codes) can use the
// server-side value; callers must never accept a secret from a request.
func Pending2FASecret(uuid string) (string, bool) {
	pendingTwoFactorMu.Lock()
	defer pendingTwoFactorMu.Unlock()
	pending, ok := pendingTwoFactors[uuid]
	if !ok {
		return "", false
	}
	if time.Now().After(pending.expires) {
		delete(pendingTwoFactors, uuid)
		return "", false
	}
	return pending.secret, true
}

// ClearPending2FA drops the pending enrollment for a user.
func ClearPending2FA(uuid string) {
	pendingTwoFactorMu.Lock()
	delete(pendingTwoFactors, uuid)
	pendingTwoFactorMu.Unlock()
}

// Get2FaSecret returns the currently enabled secret, or "" when 2FA is off.
func Get2FaSecret(uuid string) (string, error) {
	var user models.User
	if err := dbcore.GetDBInstance().Where("uuid = ?", uuid).First(&user).Error; err != nil {
		return "", err
	}
	return user.TwoFactor, nil
}

// Complete2FAEnrollment validates a pending enrollment and stores it.
//
// currentCode is required when the account already has a secret; the new code
// must match the server-side pending secret. Both checks happen before the
// conditional UPDATE, so a rejected request never modifies the stored secret.
func Complete2FAEnrollment(uuid, newCode, currentCode string) error {
	if uuid == "" {
		return errors.New("missing user UUID")
	}
	current, err := Get2FaSecret(uuid)
	if err != nil {
		return err
	}
	if current != "" {
		if currentCode == "" {
			return ErrCurrentTwoFactorRequired
		}
		if !totp.Validate(currentCode, current) {
			return ErrCurrentTwoFactorInvalid
		}
	}
	pending, ok := Pending2FASecret(uuid)
	if !ok {
		return ErrNoPendingTwoFactor
	}
	if newCode == "" || !totp.Validate(newCode, pending) {
		return ErrInvalidTwoFactorCode
	}
	if err := Enable2Fa(uuid, current, pending); err != nil {
		return err
	}
	ClearPending2FA(uuid)
	return nil
}

// Enable2Fa stores secret only if the account still matches the state the
// caller verified: currentSecret == "" means 2FA was disabled, otherwise the
// stored value must still equal currentSecret.
func Enable2Fa(uuid, currentSecret, secret string) error {
	if uuid == "" || secret == "" {
		return errors.New("invalid 2FA state")
	}
	query := dbcore.GetDBInstance().Model(&models.User{}).Where("uuid = ?", uuid)
	if currentSecret == "" {
		query = query.Where("two_factor IS NULL OR two_factor = ''")
	} else {
		query = query.Where("two_factor = ?", currentSecret)
	}
	result := query.Update("two_factor", secret)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrTwoFactorStateChanged
	}
	return nil
}

func Verify2Fa(uuid, code string) (bool, error) {
	secret, err := Get2FaSecret(uuid)
	if err != nil {
		return false, err
	}
	// 用户未启用2FA时视为校验失败
	return secret != "" && totp.Validate(code, secret), nil
}

func Disable2Fa(uuid string) error {
	db := dbcore.GetDBInstance()
	return db.Model(&models.User{}).Where("uuid = ?", uuid).Update("two_factor", "").Error
}
