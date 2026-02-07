package auth

import (
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"strings"

	internalauth "github.com/adeilh/geminithreehackathon/internal/auth"
	rakauth "github.com/adeilh/go-rakh/auth"
	"github.com/adeilh/go-rakh/httpx"
	"github.com/labstack/echo/v4"
)

// Handler exposes auth HTTP endpoints backed by the internal service.
type Handler struct {
	svc    *internalauth.Service
	authMW echo.MiddlewareFunc
}

func NewHandler(svc *internalauth.Service) *Handler {
	return &Handler{svc: svc, authMW: svc.Middleware()}
}

// Routes returns a RouteRegistrar compatible with httpx.Server.
func (h *Handler) Routes(prefix string) httpx.RouteRegistrar {
	if prefix == "" {
		prefix = "/auth"
	}
	return func(e *httpx.Echo) {
		r := httpx.NewRouter(e, prefix)
		r.POST("/register", h.register)
		r.POST("/login", h.login)
		// Protected routes: require bearer JWT via middleware when available.
		r.POST("/refresh", h.refresh, h.authMW)
		r.POST("/logout", h.logout, h.authMW)
		r.POST("/reset", h.resetPassword, h.authMW)
		r.POST("/reset/request", h.resetToken, h.authMW)
		r.GET("/me", h.whoami, h.authMW)
	}
}

func (h *Handler) register(c echo.Context) error {
	var req RegisterRequest
	if err := c.Bind(&req); err != nil {
		return badRequest(c, "invalid request")
	}
	if err := validateEmail(req.Email); err != nil {
		return badRequest(c, err.Error())
	}
	if err := validatePassword(req.Password); err != nil {
		return badRequest(c, err.Error())
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return badRequest(c, "name required")
	}
	title, err := normalizeTitle(req.Title)
	if err != nil {
		return badRequest(c, err.Error())
	}

	metadata := normalizeMetadata(req.Metadata)
	role := ""

	// Check for role in metadata
	if metadata != nil {
		if metaRole, exists := metadata["role"]; exists {
			role = strings.ToLower(strings.TrimSpace(metaRole))
		}
	}

	if role == "" {
		role = "learner"
	}
	if metadata == nil {
		metadata = make(map[string]string)
	}
	metadata["role"] = role

	user, err := h.svc.Register(c.Request().Context(), req.Email, req.Password, name, title, metadata)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": err.Error()})
	}

	return c.JSON(http.StatusCreated, RegisterResponse{ID: user.ID, Email: user.Email, Metadata: user.Metadata})
}

func (h *Handler) login(c echo.Context) error {
	var req LoginRequest
	if err := c.Bind(&req); err != nil {
		return badRequest(c, "invalid request")
	}
	if err := validateEmail(req.Email); err != nil {
		return badRequest(c, err.Error())
	}
	if err := validatePassword(req.Password); err != nil {
		return badRequest(c, err.Error())
	}

	ip := clientIP(c)
	ua := c.Request().UserAgent()
	res, err := h.svc.Login(c.Request().Context(), internalauth.LoginRequest{Email: req.Email, Password: req.Password, IP: ip, UserAgent: ua})
	if err != nil {
		status := http.StatusUnauthorized
		if err == internalauth.ErrUserDisabled {
			status = http.StatusForbidden
		}
		if err == internalauth.ErrInvalidCredentials {
			status = http.StatusUnauthorized
		}
		return c.JSON(status, echo.Map{"error": err.Error()})
	}

	// Get role from the token we just created
	token, _ := h.svc.ParseToken(c.Request().Context(), res.AccessToken)
	role := "learner" // default
	if token != nil {
		role = getRoleFromTokenContext(token.Claims())
	}

	return c.JSON(http.StatusOK, LoginResponse{
		AccessToken:      res.AccessToken,
		AccessExpiresAt:  res.AccessExpiresAt,
		SessionID:        res.SessionID,
		SessionExpiresAt: res.SessionExpiresAt,
		Role:             role,
		Name:             res.User.Name,
		Title:            res.User.Title,
	})
}

func (h *Handler) refresh(c echo.Context) error {
	var req RefreshRequest
	if err := c.Bind(&req); err != nil {
		return badRequest(c, "invalid request")
	}
	if err := validateSessionID(req.SessionID); err != nil {
		return badRequest(c, err.Error())
	}

	res, err := h.svc.RefreshSession(c.Request().Context(), req.SessionID)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, echo.Map{
		"access_token":       res.AccessToken,
		"access_expires_at":  res.AccessExpiresAt,
		"session_id":         res.SessionID,
		"session_expires_at": res.SessionExpiresAt,
	})
}

func (h *Handler) logout(c echo.Context) error {
	var req LogoutRequest
	if err := c.Bind(&req); err != nil {
		return badRequest(c, "invalid request")
	}
	if err := validateSessionID(req.SessionID); err != nil {
		return badRequest(c, err.Error())
	}
	if err := h.svc.Logout(c.Request().Context(), req.SessionID); err != nil {
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": err.Error()})
	}
	return c.NoContent(http.StatusNoContent)
}

func (h *Handler) resetPassword(c echo.Context) error {
	var req ResetPasswordRequest
	if err := c.Bind(&req); err != nil {
		return badRequest(c, "invalid request")
	}
	if err := validateEmail(req.Email); err != nil {
		return badRequest(c, err.Error())
	}
	if err := validatePassword(req.NewPassword); err != nil {
		return badRequest(c, err.Error())
	}

	if _, err := h.svc.ResetPassword(c.Request().Context(), req.Email, req.NewPassword); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": err.Error()})
	}
	return c.NoContent(http.StatusNoContent)
}

func (h *Handler) resetToken(c echo.Context) error {
	var req ResetTokenRequest
	if err := c.Bind(&req); err != nil {
		return badRequest(c, "invalid request")
	}
	if err := validateEmail(req.Email); err != nil {
		return badRequest(c, err.Error())
	}
	if _, err := h.svc.SendPasswordReset(c.Request().Context(), req.Email); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": err.Error()})
	}
	return c.NoContent(http.StatusNoContent)
}

func (h *Handler) whoami(c echo.Context) error {
	if token, ok := h.svc.TokenFromContext(c.Request().Context()); ok {
		claims := token.Claims()
		role := getRoleFromTokenContext(claims)
		return c.JSON(http.StatusOK, WhoAmIResponse{UserID: claims.Subject, Role: role})
	}

	raw := bearerToken(c.Request())
	if raw == "" {
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": "missing bearer token"})
	}
	tok, err := h.svc.ParseToken(c.Request().Context(), raw)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": err.Error()})
	}
	claims := tok.Claims()
	role := getRoleFromTokenContext(claims)
	return c.JSON(http.StatusOK, WhoAmIResponse{UserID: claims.Subject, Role: role})
}

func clientIP(c echo.Context) string {
	hdr := c.Request().Header.Get("X-Forwarded-For")
	if hdr != "" {
		parts := strings.Split(hdr, ",")
		if len(parts) > 0 && strings.TrimSpace(parts[0]) != "" {
			return strings.TrimSpace(parts[0])
		}
	}
	return c.RealIP()
}

func bearerToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return ""
	}
	const prefix = "Bearer "
	if strings.HasPrefix(strings.ToLower(authHeader), strings.ToLower(prefix)) {
		return strings.TrimSpace(authHeader[len(prefix):])
	}
	return ""
}

func badRequest(c echo.Context, msg string) error {
	return c.JSON(http.StatusBadRequest, echo.Map{"error": msg})
}

func validateEmail(email string) error {
	if strings.TrimSpace(email) == "" {
		return errors.New("email required")
	}
	if _, err := mail.ParseAddress(email); err != nil {
		return errors.New("invalid email")
	}
	return nil
}

func validatePassword(pw string) error {
	pw = strings.TrimSpace(pw)
	if len(pw) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	if len(pw) > 128 {
		return errors.New("password too long")
	}
	// Reject inputs that look like already-hashed bcrypt/argon strings to avoid double-hash misuse.
	if strings.HasPrefix(pw, "$2") || strings.HasPrefix(pw, "$argon2") {
		return errors.New("password must be a plaintext secret")
	}
	return nil
}

func normalizeTitle(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("title required")
	}
	raw = strings.TrimSuffix(raw, ".")
	switch strings.ToLower(raw) {
	case "mr":
		return "Mr", nil
	case "ms":
		return "Ms", nil
	case "mrs":
		return "Mrs", nil
	default:
		return "", errors.New("title must be Mr, Ms, or Mrs")
	}
}

func validateSessionID(id string) error {
	if strings.TrimSpace(id) == "" {
		return errors.New("session_id required")
	}
	return nil
}

func normalizeMetadata(in map[string]interface{}) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		if strings.TrimSpace(k) == "" {
			continue
		}
		out[k] = fmt.Sprint(v)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// getRoleFromTokenContext extracts the role from JWT claims
func getRoleFromTokenContext(claims rakauth.JWTClaims) string {
	if claims.Metadata != nil {
		if rawRole, exists := claims.Metadata["role"]; exists {
			// Handle different possible types
			switch role := rawRole.(type) {
			case string:
				if strings.TrimSpace(role) != "" {
					return strings.ToLower(strings.TrimSpace(role))
				}
			case nil:
				// Role key exists but is nil
			default:
				// Try to convert to string
				if strRole := strings.TrimSpace(fmt.Sprint(role)); strRole != "" {
					return strings.ToLower(strRole)
				}
			}
		}
	}
	return "learner" // default role
}
