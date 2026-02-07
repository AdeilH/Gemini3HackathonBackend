package router

import (
	internalauth "github.com/adeilh/geminithreehackathon/internal/auth"
	"github.com/adeilh/geminithreehackathon/internal/videoassessment"
	pkgVideoAssessment "github.com/adeilh/geminithreehackathon/pkg/videoassessment"
	"github.com/adeilh/go-rakh/httpx"
)

// RegisterAuth mounts auth HTTP endpoints onto the httpx server.
func RegisterVideoAssessment(server *httpx.Server, svc *videoassessment.Service, authSvc *internalauth.Service, prefix string) {
	handler := pkgVideoAssessment.NewHandler(svc, authSvc)
	server.RegisterRoutes(handler.Routes(prefix))
}

// RegisterAuthDefault mounts auth endpoints at /auth.
func RegisterVideoAssessmentDefault(server *httpx.Server, svc *videoassessment.Service, authSvc *internalauth.Service) {
	RegisterVideoAssessment(server, svc, authSvc, "")
}
