package auth

import (
	"time"

	rakauth "github.com/adeilh/go-rakh/auth"
	"github.com/adeilh/go-rakh/cache"
	rredis "github.com/adeilh/go-rakh/cache/redis"
)

// Config captures the knobs required to bootstrap the auth service.
type Config struct {
	PostgresDSN     string
	Redis           rredis.Options
	JWTSecret       string
	JWTAlgorithms   []string
	JWTIssuer       string
	JWTPrefix       string
	AccessTokenTTL  time.Duration
	SessionPrefix   string
	SessionTTL      time.Duration
	BcryptCost      int
	ResetTokenMaker func() (string, error)
	ResetSender     rakauth.PasswordResetSender
	Now             func() time.Time

	Cache          cache.Store
	UserRepository rakauth.UserRepository
}
