package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/komari-monitor/komari/database/dbcore"
	"github.com/komari-monitor/komari/database/models"
	"github.com/komari-monitor/komari/internal/config"
	v2 "github.com/komari-monitor/komari/protocol/v2"
	"github.com/komari-monitor/komari/pkg/rpc"
	agent_runtime "github.com/komari-monitor/komari/web/agent"
)

// clientStreamAccess 是公共状态流单次请求允许的可见范围。
type clientStreamAccess int

const (
	// clientStreamDenied 表示私有站点开启，且当前主体既没有有效凭据也没有
	// 临时访问许可，不能返回任何节点数据。
	clientStreamDenied clientStreamAccess = iota
	// clientStreamPublic 是游客视图：隐藏节点必须被过滤。
	clientStreamPublic
	// clientStreamFull 是管理员视图：可见全部节点。
	clientStreamFull
)

// resolveClientStreamAccess 按当前凭据重新评估访问范围。
//
// IdentifyPrincipal 每次都会重新校验 API Key、会话（含删除与过期）和 agent
// token，不会读取 IdentityMiddleware 在握手时写入的 principal 缓存；
// RefreshPrincipal 再用最新结果覆盖 gin.Context 中的 role 等兼容键，避免本次
// 请求的后续代码继续读到握手时的身份。
func resolveClientStreamAccess(c *gin.Context) (clientStreamAccess, error) {
	p := IdentifyPrincipal(c)
	RefreshPrincipal(c, p)

	privateSite, err := config.GetAs[bool](config.PrivateSiteKey, false)
	if err != nil {
		// 读不到开关时不能假定站点是公开的。
		return clientStreamDenied, err
	}
	if privateSite && p.Type == rpc.PrincipalAnonymous && !hasTempAccess(c) {
		return clientStreamDenied, nil
	}
	if p.HasRole(rpc.RoleAdmin) {
		return clientStreamFull, nil
	}
	return clientStreamPublic, nil
}

// hiddenClientUUIDs 读取当前的隐藏节点集合。
//
// 查询失败必须向调用方返回错误：把失败当成“没有隐藏节点”会把受保护节点
// 泄露给游客。
func hiddenClientUUIDs() (map[string]bool, error) {
	var uuids []string
	db := dbcore.GetDBInstance()
	if err := db.Model(&models.Client{}).Where("hidden = ?", true).Pluck("uuid", &uuids).Error; err != nil {
		return nil, err
	}
	hidden := make(map[string]bool, len(uuids))
	for _, uuid := range uuids {
		hidden[uuid] = true
	}
	return hidden, nil
}

func GetClients(c *gin.Context) {
	// 升级到ws
	if !IsWebSocketUpgrade(c) {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "Require WebSocket upgrade"})
		return
	}
	// Upgrade the HTTP connection to a WebSocket connection
	conn, err := UpgradeSafeConnWithLimit(c, MaxPublicStreamMessageBytes, EnableWebSocketCompression)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "Failed to upgrade to WebSocket." + err.Error()})
		return
	}
	defer conn.Close()

	// 请求
	for {
		resp := struct {
			Online []string             `json:"online"` // 已建立连接的客户端uuid列表
			Data   map[string]v2.Report `json:"data"`   // 最后上报的数据
		}{Online: []string{}, Data: map[string]v2.Report{}}

		_, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		message := string(data)

		uuID := ""
		if message != "get" { // 非请求全部内容
			if strings.HasPrefix(message, "get ") {
				uuID = strings.TrimSpace(strings.TrimPrefix(message, "get "))
			} else {
				conn.WriteJSON(gin.H{"status": "error", "error": "Invalid message"})
				continue
			}
		}

		// 每条 get 都重新鉴权：Session 删除/过期、API Key 轮换、私有站点
		// 开关以及临时访问许可变化都会在下一次请求时生效。
		access, err := resolveClientStreamAccess(c)
		if err != nil {
			conn.WriteJSON(gin.H{"status": "error", "error": "Failed to resolve client access."})
			continue
		}
		if access == clientStreamDenied {
			conn.WriteJSON(gin.H{"status": "error", "error": "Private site is enabled, please login first."})
			_ = conn.WriteControl(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "authentication required"),
				time.Now().Add(time.Second))
			return
		}

		// 只有管理员视图可以跳过隐藏节点查询；游客视图每次都读取最新可见性，
		// 不能复用握手时的 hiddenMap。
		hiddenMap := map[string]bool{}
		if access != clientStreamFull {
			hiddenMap, err = hiddenClientUUIDs()
			if err != nil {
				// 无法确认可见性时拒绝返回数据。
				conn.WriteJSON(gin.H{"status": "error", "error": "Failed to load client visibility."})
				continue
			}
		}

		// 在线客户端uuid列表（WebSocket 与非 WebSocket）
		for _, key := range agent_runtime.GetAllOnlineUUIDs() {
			if hiddenMap[key] {
				continue
			}
			if uuID != "" && key != uuID {
				continue
			}
			resp.Online = append(resp.Online, key)
		}

		//过往节点数据信息
		for key, report := range agent_runtime.GetLatestReport() {
			if hiddenMap[key] {
				continue
			}
			if uuID != "" && key != uuID {
				continue
			}

			report.UUID = "" // 不暴露 uuid
			if report.CPU.Usage == 0 {
				report.CPU.Usage = 0.01
			}
			resp.Data[key] = *report
		}

		if err := conn.WriteJSON(gin.H{"status": "success", "data": resp}); err != nil {
			return
		}
	}
}
