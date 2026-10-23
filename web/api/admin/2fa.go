package admin

import (
	"errors"
	"image/png"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/komari-monitor/komari/database/accounts"
	"github.com/komari-monitor/komari/utils"
	"github.com/komari-monitor/komari/web/api"
)

func Generate2FA(c *gin.Context) {
	uuid := c.GetString("uuid")
	if uuid == "" {
		api.RespondError(c, http.StatusUnauthorized, "Unauthorized.")
		return
	}
	// 待绑定密钥由服务端生成并绑定到当前用户与有效期；cookie 只保存一个
	// 不透明的会话标记，enable 不会再读取客户端提供的密钥。
	if _, img, err := accounts.Begin2FaEnrollment(uuid); err != nil {
		api.RespondError(c, http.StatusInternalServerError, "Failed to generate 2FA: "+err.Error())
		return
	} else {
		c.SetCookie("2fa_secret", utils.GenerateRandomString(32), 1800, "/", "", false, true)
		c.Header("Content-Type", "image/png")
		c.Writer.WriteHeader(http.StatusOK)
		png.Encode(c.Writer, img)
	}
}

// Enable2FA 完成一次 2FA 绑定。
//
// 首次启用只需要待绑定密钥对应的 code；账号已启用 2FA 时必须同时提交当前
// 第二因素（current_code / X-Current-2FA-Code），否则拒绝，避免仅凭登录会话
// 覆盖已有密钥。所有校验都在写入前完成，失败不会修改原密钥。
func Enable2FA(c *gin.Context) {
	uuid := c.GetString("uuid")
	code := c.Query("code")
	if uuid == "" {
		api.RespondError(c, http.StatusUnauthorized, "Unauthorized.")
		return
	}
	if code == "" {
		api.RespondError(c, http.StatusBadRequest, "2FA code not provided")
		return
	}
	currentCode := c.Query("current_code")
	if currentCode == "" {
		currentCode = c.GetHeader("X-Current-2FA-Code")
	}
	err := accounts.Complete2FAEnrollment(uuid, code, currentCode)
	switch {
	case err == nil:
		c.SetCookie("2fa_secret", "", -1, "/", "", false, true)
		api.RespondSuccess(c, "2FA enabled successfully")
	case errors.Is(err, accounts.ErrCurrentTwoFactorRequired),
		errors.Is(err, accounts.ErrCurrentTwoFactorInvalid):
		api.RespondError(c, http.StatusForbidden, err.Error())
	case errors.Is(err, accounts.ErrNoPendingTwoFactor),
		errors.Is(err, accounts.ErrInvalidTwoFactorCode):
		api.RespondError(c, http.StatusBadRequest, err.Error())
	case errors.Is(err, accounts.ErrTwoFactorStateChanged):
		api.RespondError(c, http.StatusConflict, err.Error())
	default:
		api.RespondError(c, http.StatusInternalServerError, "Failed to enable 2FA: "+err.Error())
	}
}

func Disable2FA(c *gin.Context) {
	uuid := c.GetString("uuid")
	if uuid == "" {
		api.RespondError(c, http.StatusUnauthorized, "Unauthorized.")
		return
	}
	err := accounts.Disable2Fa(uuid)
	if err != nil {
		api.RespondError(c, http.StatusInternalServerError, "Failed to disable 2FA: "+err.Error())
		return
	}
	accounts.ClearPending2FA(uuid)
	api.RespondSuccess(c, "")
}
