# httpx

Echo-powered HTTP server wrapper plus Resty-based client helpers for quick service wiring.

## Server
```go
import "github.com/adeilh/go-rakh/httpx"

srv := httpx.NewServer(
    httpx.WithAddress(":8081"),
)
srv.RegisterRoutes(func(e *httpx.Echo) {
    e.GET("/ping", func(c httpx.Context) error {
        return c.JSON(httpx.StatusOK, map[string]string{"message": "pong"})
    })
})
```

## Auth middleware (Echo)
```go
amw, _ := auth.NewMiddleware(tokenParser)
srv := httpx.NewServer(httpx.WithMiddlewares(httpx.AuthMiddleware(amw)))
srv.RegisterRoutes(func(e *httpx.Echo) {
    e.GET("/secure", func(c httpx.Context) error {
        tok, ok := auth.TokenFromContext(c.Request().Context())
        if !ok {
            return c.JSON(httpx.StatusUnauthorized, map[string]string{"error": "missing token"})
        }
        return c.JSON(httpx.StatusOK, tok.Claims())
    })
})
```

## Client
```go
c := httpx.NewClient(httpx.WithBaseURL("http://localhost:8081"))
var out map[string]string
_, err := c.Get(ctx, "/ping", &out, httpx.WithQuery(map[string]string{"foo": "bar"}))
```

## Common status codes
See `httpx/status.go` for guidance on when to use:
- 200/201/204 for success
- 400 for validation, 401/403 for authz, 404 not found
- 409 conflict, 422 semantic issues, 429 rate limits
- 500/503 for server/dependency issues

## Echo wrapper (integration guide)
Use the httpx-provided Echo aliases to avoid importing `echo/v4` directly.

- Types: `httpx.Echo`, `httpx.Context`, `httpx.HandlerFunc`, `httpx.MiddlewareFunc`
- Common middleware: `httpx.LoggerMiddleware()`, `httpx.RecoverMiddleware()`, `httpx.CORSMiddleware(cfg)`.

```go
srv := httpx.NewServer(
    httpx.WithMiddlewares(httpx.LoggerMiddleware(), httpx.RecoverMiddleware()),
)

srv.RegisterRoutes(func(e *httpx.Echo) {
    // Global routes
    e.GET("/health", func(c httpx.Context) error { return c.NoContent(httpx.StatusOK) })

    // Grouped routes with shared middleware
    api := httpx.NewRouter(e, "/api")
    api.GET("/ping", func(c httpx.Context) error {
        return c.JSON(httpx.StatusOK, map[string]string{"message": "pong"})
    })
})
```

### Middleware helpers
- `httpx.MiddlewareFunc`, `httpx.HandlerFunc`, `httpx.Context` mirror Echo types.
- Common middleware: `httpx.LoggerMiddleware()`, `httpx.RecoverMiddleware()`, `httpx.CORSMiddleware(cfg)`.

### Routing helpers
- `httpx.Route` + `httpx.RegisterRoutes(e, routes...)` for bulk registration.
- `httpx.NewRouter(e, prefix, mw...)` for chainable `GET/POST/PUT/DELETE` on a group.

### Auth bridge
Wrap `auth.Middleware` for Echo without importing Echo types:
```go
amw, _ := auth.NewMiddleware(manager)
srv := httpx.NewServer(httpx.WithMiddlewares(httpx.AuthMiddleware(amw)))
```

### Validation hooks
Attach request validators at server creation:
```go
srv := httpx.NewServer(httpx.WithValidators(func(c httpx.Context) error {
    if c.Request().Header.Get("X-Trace") == "" {
        return c.JSON(httpx.StatusBadRequest, map[string]string{"error": "missing trace id"})
    }
    return nil
}))
```

### CORS and custom logger
```go
cors := httpx.DefaultCORSConfig
cors.AllowOrigins = []string{"https://app.example.com"}
srv := httpx.NewServer(
    httpx.WithCORS(&cors),
    httpx.WithLogger(customEchoLogger),
)
```

### Client pairing
Use `httpx.NewClient` and request options like `WithBearer` / `WithQuery` to talk to these routes.
