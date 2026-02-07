package auth

import (
	"context"
	"sync"
	"testing"
	"time"

	rakauth "github.com/adeilh/go-rakh/auth"
	rkcache "github.com/adeilh/go-rakh/cache"
)

type memoryItem struct {
	value []byte
	exp   time.Time
}

type memoryStore struct {
	mu   sync.Mutex
	data map[string]memoryItem
}

func newMemoryStore() *memoryStore {
	return &memoryStore{data: map[string]memoryItem{}}
}

func (s *memoryStore) Get(ctx context.Context, key string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.data[key]
	if !ok {
		return nil, rkcache.ErrNotFound
	}
	if !item.exp.IsZero() && time.Now().After(item.exp) {
		delete(s.data, key)
		return nil, rkcache.ErrNotFound
	}
	return item.value, nil
}

func (s *memoryStore) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[key] = memoryItem{value: value, exp: time.Now().Add(ttl)}
	return nil
}

func (s *memoryStore) Delete(ctx context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, key)
	return nil
}

type memoryRepo struct {
	mu      sync.Mutex
	byEmail map[string]rakauth.User
	byID    map[string]rakauth.User
}

func newMemoryRepo() *memoryRepo {
	return &memoryRepo{byEmail: map[string]rakauth.User{}, byID: map[string]rakauth.User{}}
}

func (r *memoryRepo) CreateUser(ctx context.Context, user rakauth.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !user.Enabled {
		user.Enabled = true
	}
	r.byEmail[user.Email] = user
	r.byID[user.ID] = user
	return nil
}

func (r *memoryRepo) UpdateUser(ctx context.Context, user rakauth.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byEmail[user.Email] = user
	r.byID[user.ID] = user
	return nil
}

func (r *memoryRepo) UpdateUserPartial(ctx context.Context, userID string, patch rakauth.UserPatch) (rakauth.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.byID[userID]
	if !ok {
		return rakauth.User{}, rakauth.ErrUserNotFound
	}
	if patch.Email != nil {
		delete(r.byEmail, u.Email)
		u.Email = *patch.Email
	}
	if patch.PasswordHash != nil {
		u.PasswordHash = *patch.PasswordHash
	}
	if patch.Metadata != nil {
		u.Metadata = patch.Metadata
	}
	r.byID[userID] = u
	r.byEmail[u.Email] = u
	return u, nil
}

func (r *memoryRepo) DeleteUser(ctx context.Context, userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if u, ok := r.byID[userID]; ok {
		delete(r.byEmail, u.Email)
		delete(r.byID, userID)
	}
	return nil
}

func (r *memoryRepo) DisableUser(ctx context.Context, userID string) (rakauth.User, error) {
	return r.applyFlag(ctx, userID, "true")
}

func (r *memoryRepo) EnableUser(ctx context.Context, userID string) (rakauth.User, error) {
	return r.applyFlag(ctx, userID, "false")
}

func (r *memoryRepo) applyFlag(ctx context.Context, userID, disabled string) (rakauth.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.byID[userID]
	if !ok {
		return rakauth.User{}, rakauth.ErrUserNotFound
	}
	if u.Metadata == nil {
		u.Metadata = map[string]string{}
	}
	u.Metadata["disabled"] = disabled
	u.Enabled = disabled == "false"
	r.byID[userID] = u
	r.byEmail[u.Email] = u
	return u, nil
}

func (r *memoryRepo) GetUserByEmail(ctx context.Context, email string) (rakauth.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.byEmail[email]
	if !ok {
		return rakauth.User{}, rakauth.ErrUserNotFound
	}
	return u, nil
}

type mockResetSender struct {
	mu     sync.Mutex
	user   rakauth.User
	token  string
	called bool
}

func (m *mockResetSender) SendResetToken(ctx context.Context, user rakauth.User, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.user = user
	m.token = token
	m.called = true
	return nil
}

func newTestService(t *testing.T) (*Service, *memoryRepo, *mockResetSender) {
	t.Helper()

	store := newMemoryStore()
	repo := newMemoryRepo()
	hasher := NewBcryptHasher(0, nil)
	sender := &mockResetSender{}
	now := time.Now

	jwtOpts := rakauth.JWTOptions{Issuer: "test", TTL: time.Hour}

	manager, err := rakauth.NewManager(rakauth.ManagerConfig{
		Cache:          store,
		JWTSecret:      []byte("secret"),
		JWTAlgorithms:  []string{"HS256"},
		JWTOptions:     jwtOpts,
		SessionOptions: rakauth.SessionStoreOptions{Prefix: "sess", DefaultTTL: time.Hour},
		UserRepository: repo,
		PasswordHasher: hasher,
		ResetSender:    sender,
		ResetTokenMaker: func() (string, error) {
			return "reset-token", nil
		},
		Now: now,
	})
	if err != nil {
		t.Fatalf("failed to build manager: %v", err)
	}

	svc := &Service{
		manager:    manager,
		repo:       repo,
		hasher:     hasher,
		jwtOpts:    jwtOpts,
		sessionTTL: time.Hour,
		now:        now,
		bcryptCost: hasher.cost,
	}

	return svc, repo, sender
}

func TestAddUserAndDisable(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()

	user, err := svc.AddUser(ctx, "a@example.com", "pass123", "Test User", "Mr", map[string]string{"role": "user"})
	if err != nil {
		t.Fatalf("AddUser error: %v", err)
	}
	if user.ID == "" {
		t.Fatalf("expected user ID to be set")
	}
	if !user.Enabled {
		t.Fatalf("expected new user enabled")
	}

	disabled, err := svc.DisableUser(ctx, "a@example.com")
	if err != nil {
		t.Fatalf("DisableUser error: %v", err)
	}
	if disabled.Enabled {
		t.Fatalf("expected user to be disabled")
	}
	if disabled.Metadata["disabled"] != "true" {
		t.Fatalf("expected disabled flag set, got %v", disabled.Metadata)
	}

	if _, err := svc.Login(ctx, LoginRequest{Email: "a@example.com", Password: "pass123"}); err == nil {
		t.Fatalf("expected login to fail for disabled user")
	}
}

func TestLoginFlow(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()

	user, err := svc.AddUser(ctx, "b@example.com", "secret", "Test User", "Ms", nil)
	if err != nil {
		t.Fatalf("AddUser error: %v", err)
	}

	res, err := svc.Login(ctx, LoginRequest{Email: "b@example.com", Password: "secret", IP: "127.0.0.1", UserAgent: "test-agent"})
	if err != nil {
		t.Fatalf("Login error: %v", err)
	}
	if res.AccessToken == "" {
		t.Fatalf("expected access token")
	}
	tok, err := svc.ParseToken(ctx, res.AccessToken)
	if err != nil {
		t.Fatalf("ParseToken error: %v", err)
	}
	if tok.Claims().Subject != user.ID {
		t.Fatalf("token subject mismatch: got %s want %s", tok.Claims().Subject, user.ID)
	}

	if err := svc.Logout(ctx, res.SessionID); err != nil {
		t.Fatalf("Logout error: %v", err)
	}
}

func TestResetPassword(t *testing.T) {
	svc, _, sender := newTestService(t)
	ctx := context.Background()

	if _, err := svc.AddUser(ctx, "c@example.com", "oldpass", "Test User", "Mrs", nil); err != nil {
		t.Fatalf("AddUser error: %v", err)
	}

	// Send reset to ensure token path works
	token, err := svc.SendPasswordReset(ctx, "c@example.com")
	if err != nil {
		t.Fatalf("SendPasswordReset error: %v", err)
	}
	if token == "" || !sender.called {
		t.Fatalf("expected reset sender to be invoked")
	}

	if _, err := svc.ResetPassword(ctx, "c@example.com", "newpass"); err != nil {
		t.Fatalf("ResetPassword error: %v", err)
	}

	// Old password should fail
	if _, err := svc.Login(ctx, LoginRequest{Email: "c@example.com", Password: "oldpass"}); err == nil {
		t.Fatalf("expected login with old password to fail")
	}

	// New password should succeed
	if _, err := svc.Login(ctx, LoginRequest{Email: "c@example.com", Password: "newpass"}); err != nil {
		t.Fatalf("login with new password failed: %v", err)
	}
}
