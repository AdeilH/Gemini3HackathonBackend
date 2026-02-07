package auth

import "time"

// RegisterRequest captures new user inputs.
type RegisterRequest struct {
	Email    string                 `json:"email"`
	Password string                 `json:"password"`
	Name     string                 `json:"name"`
	Title    string                 `json:"title"`
	Metadata map[string]interface{} `json:"metadata"`
}

// RegisterResponse returns the created user basics.
type RegisterResponse struct {
	ID       string            `json:"id"`
	Email    string            `json:"email"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// LoginRequest is the payload for login.
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginResponse bundles tokens and session info.
type LoginResponse struct {
	AccessToken      string    `json:"access_token"`
	AccessExpiresAt  time.Time `json:"access_expires_at"`
	SessionID        string    `json:"session_id"`
	SessionExpiresAt time.Time `json:"session_expires_at"`
	Role             string    `json:"role"`
	Name             string    `json:"name"`
	Title            string    `json:"title"`
}

// RefreshRequest carries the session identifier.
type RefreshRequest struct {
	SessionID string `json:"session_id"`
}

// LogoutRequest carries the session identifier to delete.
type LogoutRequest struct {
	SessionID string `json:"session_id"`
}

// ResetPasswordRequest changes a user's password directly.
type ResetPasswordRequest struct {
	Email       string `json:"email"`
	NewPassword string `json:"new_password"`
}

// ResetTokenRequest triggers a password reset token delivery.
type ResetTokenRequest struct {
	Email string `json:"email"`
}

// WhoAmIResponse returns the caller identity from JWT claims.
type WhoAmIResponse struct {
	UserID string `json:"user_id"`
	Email  string `json:"email,omitempty"`
	Role   string `json:"role"`
}
