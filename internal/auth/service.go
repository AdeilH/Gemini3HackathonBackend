package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	rakauth "github.com/adeilh/go-rakh/auth"
	rkcache "github.com/adeilh/go-rakh/cache"
	rredis "github.com/adeilh/go-rakh/cache/redis"
	dbpg "github.com/adeilh/go-rakh/db/sql/postgres"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	_ "github.com/lib/pq"
)

var (
	ErrInvalidCredentials = errors.New("auth: invalid credentials")
	ErrMissingConfig      = errors.New("auth: missing critical auth config")
	ErrUserDisabled       = errors.New("auth: user disabled")
)

// Service wires the go-rakh manager with local convenience helpers for REST.
type Service struct {
	manager    *rakauth.Manager
	repo       rakauth.UserRepository
	hasher     rakauth.PasswordHasher
	jwtOpts    rakauth.JWTOptions
	sessionTTL time.Duration
	now        func() time.Time
	db         *sql.DB
	bcryptCost int
}

// LoginRequest bundles the inputs required for a login flow.
type LoginRequest struct {
	Email     string
	Password  string
	IP        string
	UserAgent string
	Metadata  map[string]string
}

// LoginResponse captures the auth artifacts produced during login.
type LoginResponse struct {
	User             rakauth.User
	AccessToken      string
	AccessExpiresAt  time.Time
	SessionID        string
	SessionExpiresAt time.Time
}

// RefreshResponse captures the artifacts produced during a session refresh.
type RefreshResponse struct {
	AccessToken      string
	AccessExpiresAt  time.Time
	SessionID        string
	SessionExpiresAt time.Time
}

// NewService composes cache, repo, hasher, and manager so REST handlers can call simple methods.
func NewService(cfg Config) (*Service, error) {
	if len(cfg.JWTSecret) == 0 {
		return nil, ErrMissingConfig
	}

	if cfg.UserRepository == nil && cfg.PostgresDSN == "" {
		return nil, ErrMissingConfig
	}

	now := cfg.Now
	if now == nil {
		now = time.Now
	}

	var cacheStore rkcache.Store
	if cfg.Cache != nil {
		cacheStore = cfg.Cache
	} else {
		cacheStore = rredis.NewStore(cfg.Redis)
	}

	var db *sql.DB
	repo := cfg.UserRepository
	if repo == nil {
		var err error
		db, err = sql.Open("postgres", cfg.PostgresDSN)
		if err != nil {
			return nil, err
		}
		repo = dbpg.NewUserRepository(db)
	}

	hasher := NewBcryptHasher(cfg.BcryptCost, nil)

	jwtOpts := rakauth.JWTOptions{
		Issuer:   cfg.JWTIssuer,
		TTL:      cfg.AccessTokenTTL,
		KeyID:    "",
		Audience: nil,
	}

	manager, err := rakauth.NewManager(rakauth.ManagerConfig{
		Cache:          cacheStore,
		JWTSecret:      []byte(cfg.JWTSecret),
		JWTAlgorithms:  cfg.JWTAlgorithms,
		JWTOptions:     jwtOpts,
		SessionOptions: rakauth.SessionStoreOptions{Prefix: cfg.SessionPrefix, DefaultTTL: cfg.SessionTTL},
		UserRepository: repo,
		PasswordHasher: hasher,
		ResetSender:    cfg.ResetSender,
		ResetTokenMaker: func() (string, error) {
			if cfg.ResetTokenMaker != nil {
				return cfg.ResetTokenMaker()
			}
			return uuid.NewString(), nil
		},
		Now: now,
	})
	if err != nil {
		if db != nil {
			err := db.Close()
			if err != nil {
				return nil, err
			}
		}
		return nil, err
	}

	return &Service{
		manager:    manager,
		repo:       repo,
		hasher:     hasher,
		jwtOpts:    jwtOpts,
		sessionTTL: cfg.SessionTTL,
		now:        now,
		db:         db,
		bcryptCost: cfg.BcryptCost,
	}, nil
}

// Close releases database resources.
func (s *Service) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Service) DB() *sql.DB {
	return s.db
}

// Register creates a user with hashed password.
func (s *Service) Register(ctx context.Context, email, password, name, title string, metadata map[string]string) (rakauth.User, error) {
	if metadata == nil {
		metadata = map[string]string{}
	}

	pwHash, err := s.hasher.Hash(ctx, []byte(password), rakauth.PasswordOptions{Cost: s.bcryptCost})
	if err != nil {
		return rakauth.User{}, err
	}

	now := s.now()
	name = strings.TrimSpace(name)
	title = strings.TrimSpace(title)
	user := rakauth.User{
		ID:           newUUIDv7(),
		Email:        email,
		Name:         name,
		Title:        title,
		PasswordHash: pwHash,
		Metadata:     metadata,
		Enabled:      true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := s.repo.CreateUser(ctx, user); err != nil {
		return rakauth.User{}, err
	}
	if s.db != nil {
		if name != "" || title != "" {
			if err := s.updateUserProfile(ctx, user.ID, name, title); err != nil {
				return rakauth.User{}, err
			}
		}
	}
	return user, nil
}

// Login validates credentials, issues a JWT, and creates a session.
func (s *Service) Login(ctx context.Context, req LoginRequest) (LoginResponse, error) {
	var out LoginResponse

	user, err := s.repo.GetUserByEmail(ctx, req.Email)
	if err != nil {
		return out, err
	}

	if !user.Enabled {
		return out, ErrUserDisabled
	}

	if err := s.hasher.Compare(ctx, []byte(req.Password), user.PasswordHash); err != nil {
		return out, ErrInvalidCredentials
	}

	// Opportunistically upgrade hash if cost changed.
	if s.hasher.NeedsRehash(user.PasswordHash, rakauth.PasswordOptions{Cost: s.bcryptCost}) {
		if updated, err := s.manager.UpdateUser(ctx, user, []byte(req.Password)); err == nil {
			user = updated
		}
	}

	now := s.now()

	// Get user role for JWT claims
	role, err := s.GetUserRole(ctx, user.ID)
	if err != nil || role == "" {
		// If role lookup fails or returns empty, default to "learner"
		role = "learner"
	}

	claims := rakauth.JWTClaims{
		Subject:   user.ID,
		IssuedAt:  now,
		ExpiresAt: now.Add(s.jwtOpts.TTL),
		Metadata:  map[string]any{"role": role},
	}
	token, err := s.manager.IssueToken(ctx, claims, s.jwtOpts)
	if err != nil {
		return out, err
	}

	sessionDesc := rakauth.SessionDescriptor{
		ID:        newUUIDv7(),
		Subject:   user.ID,
		IssuedAt:  now,
		ExpiresAt: now.Add(s.sessionTTL),
		IP:        req.IP,
		UserAgent: req.UserAgent,
		Metadata:  req.Metadata,
	}

	session, err := s.manager.CreateSession(ctx, sessionDesc)
	if err != nil {
		return out, err
	}

	desc := session.Descriptor()
	out.User = user
	out.AccessToken = token.Raw()
	out.AccessExpiresAt = token.ExpiresAt()
	out.SessionID = desc.ID
	out.SessionExpiresAt = desc.ExpiresAt
	return out, nil
}

// RefreshSession extends a session TTL and returns new tokens.
func (s *Service) RefreshSession(ctx context.Context, sessionID string) (RefreshResponse, error) {
	expiresAt := s.now().Add(s.sessionTTL)
	if err := s.manager.TouchSession(ctx, sessionID, expiresAt); err != nil {
		return RefreshResponse{}, err
	}

	session, err := s.manager.GetSession(ctx, sessionID)
	if err != nil {
		return RefreshResponse{}, err
	}

	desc := session.Descriptor()

	// Get user by ID using repo if it has it (postgres one has getUserByID private, but we can use email if we had it,
	// or we can just query the DB directly since we have it in Service)
	var user rakauth.User
	if s.db != nil {
		var (
			pwBytes   []byte
			metaBytes []byte
		)
		err := s.db.QueryRowContext(ctx, `
			SELECT id, email, name, title, password_hash, enabled, metadata, created_at, updated_at
			FROM users WHERE id = $1
		`, desc.Subject).Scan(
			&user.ID,
			&user.Email,
			&user.Name,
			&user.Title,
			&pwBytes,
			&user.Enabled,
			&metaBytes,
			&user.CreatedAt,
			&user.UpdatedAt,
		)
		if err != nil {
			return RefreshResponse{}, err
		}
		user.PasswordHash.Value = pwBytes
		if len(metaBytes) > 0 {
			_ = json.Unmarshal(metaBytes, &user.Metadata)
		}
	} else {
		// Fallback to repo if possible (for tests using memoryRepo)
		// We don't have email in descriptor, this is tricky.
		// For simplicity and since s.db is usually present in production:
		return RefreshResponse{}, fmt.Errorf("auth: direct db access required for refresh")
	}

	if !user.Enabled {
		return RefreshResponse{}, ErrUserDisabled
	}

	now := s.now()
	role, err := s.GetUserRole(ctx, user.ID)
	if err != nil || role == "" {
		role = "learner"
	}

	claims := rakauth.JWTClaims{
		Subject:   user.ID,
		IssuedAt:  now,
		ExpiresAt: now.Add(s.jwtOpts.TTL),
		Metadata:  map[string]any{"role": role},
	}
	token, err := s.manager.IssueToken(ctx, claims, s.jwtOpts)
	if err != nil {
		return RefreshResponse{}, err
	}

	return RefreshResponse{
		AccessToken:      token.Raw(),
		AccessExpiresAt:  token.ExpiresAt(),
		SessionID:        desc.ID,
		SessionExpiresAt: desc.ExpiresAt,
	}, nil
}

// Logout deletes a session by ID.
func (s *Service) Logout(ctx context.Context, sessionID string) error {
	return s.manager.DeleteSession(ctx, sessionID)
}

// ParseToken validates a raw JWT string and returns the parsed token.
func (s *Service) ParseToken(ctx context.Context, raw string) (rakauth.JWTToken, error) {
	return s.manager.ParseToken(ctx, raw)
}

// SendPasswordReset generates and dispatches a reset token through the configured sender.
func (s *Service) SendPasswordReset(ctx context.Context, email string) (string, error) {
	return s.manager.SendPasswordReset(ctx, email)
}

// AddUser creates a new user; helper alias to Register.
func (s *Service) AddUser(ctx context.Context, email, password, name, title string, metadata map[string]string) (rakauth.User, error) {
	return s.Register(ctx, email, password, name, title, metadata)
}

// DisableUser calls the manager to mark a user disabled.
func (s *Service) DisableUser(ctx context.Context, email string) (rakauth.User, error) {
	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		return rakauth.User{}, err
	}

	return s.manager.DisableUser(ctx, user.ID)
}

// ResetPassword updates the user's password to the new value.
func (s *Service) ResetPassword(ctx context.Context, email, newPassword string) (rakauth.User, error) {
	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		return rakauth.User{}, err
	}
	return s.manager.UpdateUser(ctx, user, []byte(newPassword))
}

// Middleware attaches the auth middleware to an Echo instance.
func (s *Service) Middleware() echo.MiddlewareFunc {
	if s == nil {
		return nil
	}
	mw, err := rakauth.NewMiddleware(s, rakauth.WithTokenExtractor(rakauth.BearerTokenExtractor()))
	if err != nil {
		return nil
	}
	return echo.WrapMiddleware(mw.Handler)
}

// TokenFromContext extracts the JWT token placed by the middleware.
func (s *Service) TokenFromContext(ctx context.Context) (rakauth.JWTToken, bool) {
	return rakauth.TokenFromContext(ctx)
}

func newUUIDv7() string {
	v7, err := uuid.NewV7()
	if err != nil {
		return uuid.NewString()
	}
	return v7.String()
}

func (s *Service) GetUserRole(ctx context.Context, userID string) (string, error) {
	if strings.TrimSpace(userID) == "" {
		return "", errors.New("auth: user id required")
	}
	if _, err := uuid.Parse(userID); err != nil {
		return "", fmt.Errorf("auth: invalid user id format: %w", err)
	}

	// Prefer repository lookup when available.
	if fetcher, ok := s.repo.(interface {
		GetUserByID(context.Context, string) (rakauth.User, error)
	}); ok {
		user, err := fetcher.GetUserByID(ctx, userID)
		if err == nil {
			return strings.ToLower(strings.TrimSpace(user.Metadata["role"])), nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return "", err
		}
	}

	if s.db == nil {
		return "", errors.New("auth: user lookup unavailable")
	}

	var metaBytes []byte
	if err := s.db.QueryRowContext(ctx, `SELECT metadata FROM users WHERE id = $1`, userID).Scan(&metaBytes); err != nil {
		return "", err
	}

	if len(metaBytes) == 0 {
		return "", nil
	}

	var meta map[string]interface{}
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return "", fmt.Errorf("auth: parse user metadata: %w", err)
	}
	if raw, ok := meta["role"]; ok {
		switch v := raw.(type) {
		case string:
			return strings.ToLower(strings.TrimSpace(v)), nil
		default:
			return strings.ToLower(strings.TrimSpace(fmt.Sprint(v))), nil
		}
	}
	return "", nil
}

func (s *Service) updateUserProfile(ctx context.Context, userID, name, title string) error {
	if s.db == nil {
		return nil
	}
	if strings.TrimSpace(name) == "" && strings.TrimSpace(title) == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE users
		SET name = $2,
		    title = $3,
		    updated_at = NOW()
		WHERE id = $1
	`, userID, name, title)
	return err
}
