package router

import (
	internalauth "github.com/adeilh/geminithreehackathon/internal/auth"
	pkgAuth "github.com/adeilh/geminithreehackathon/pkg/auth"
	"github.com/adeilh/go-rakh/httpx"
)

// RegisterAuth mounts auth HTTP endpoints onto the httpx server.
func RegisterAuth(server *httpx.Server, svc *internalauth.Service, prefix string) {
	handler := pkgAuth.NewHandler(svc)
	server.RegisterRoutes(handler.Routes(prefix))
}

// RegisterAuthDefault mounts auth endpoints at /auth.
func RegisterAuthDefault(server *httpx.Server, svc *internalauth.Service) {
	RegisterAuth(server, svc, "")
}
