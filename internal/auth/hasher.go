package auth

import (
	"context"
	"errors"
	"time"

	rakauth "github.com/adeilh/go-rakh/auth"
	"golang.org/x/crypto/bcrypt"
)

const bcryptAlgorithm = "bcrypt"

// BcryptHasher implements rakauth.PasswordHasher using bcrypt and an optional pepper.
type BcryptHasher struct {
	cost   int
	pepper []byte
}

func NewBcryptHasher(cost int, pepper []byte) BcryptHasher {
	if cost == 0 {
		cost = bcrypt.DefaultCost
	}
	return BcryptHasher{cost: cost, pepper: pepper}
}

func (h BcryptHasher) Hash(ctx context.Context, plain []byte, opts rakauth.PasswordOptions) (rakauth.PasswordHash, error) {
	select {
	case <-ctx.Done():
		return rakauth.PasswordHash{}, ctx.Err()
	default:
	}

	cost := h.cost
	if opts.Cost > 0 {
		cost = opts.Cost
	}

	payload := h.applyPepper(plain)
	hashed, err := bcrypt.GenerateFromPassword(payload, cost)
	if err != nil {
		return rakauth.PasswordHash{}, err
	}

	return rakauth.PasswordHash{
		Algorithm: bcryptAlgorithm,
		Cost:      cost,
		Value:     hashed,
		CreatedAt: time.Now(),
	}, nil
}

func (h BcryptHasher) Compare(ctx context.Context, plain []byte, hash rakauth.PasswordHash) error {
	if hash.Algorithm != "" && hash.Algorithm != bcryptAlgorithm {
		return errors.New("unsupported hash algorithm")
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	payload := h.applyPepper(plain)
	return bcrypt.CompareHashAndPassword(hash.Value, payload)
}

func (h BcryptHasher) NeedsRehash(hash rakauth.PasswordHash, opts rakauth.PasswordOptions) bool {
	if hash.Algorithm != bcryptAlgorithm {
		return true
	}

	if opts.Cost > 0 && hash.Cost != opts.Cost {
		return true
	}

	return false
}

func (h BcryptHasher) applyPepper(plain []byte) []byte {
	if len(h.pepper) == 0 {
		return plain
	}

	buf := make([]byte, 0, len(plain)+len(h.pepper))
	buf = append(buf, plain...)
	buf = append(buf, h.pepper...)
	return buf
}
