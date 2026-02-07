package videoassessment

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"time"

	internalauth "github.com/adeilh/geminithreehackathon/internal/auth"
	"github.com/adeilh/geminithreehackathon/internal/videoassessment"
	"github.com/adeilh/go-rakh/httpx"
	"github.com/labstack/echo/v4"
)

const MAX_UPLOAD_SIZE = 100 * 1024 * 1024

// Handler exposes scenario CRUD endpoints with role-based access.
type Handler struct {
	svc     *videoassessment.Service
	authSvc *internalauth.Service
	authMW  echo.MiddlewareFunc
}

func NewHandler(svc *videoassessment.Service, authSvc *internalauth.Service) *Handler {
	return &Handler{svc: svc, authSvc: authSvc, authMW: authSvc.Middleware()}
}

func (h *Handler) Routes(prefix string) httpx.RouteRegistrar {
	if prefix == "" {
		prefix = "/videoassessment"
	}
	return func(e *httpx.Echo) {
		g := e.Group(prefix)
		g.POST("/upload", h.uploadVideo, h.authMW)
	}
}

func (h *Handler) uploadVideo(c echo.Context) error {
	// Only allow post
	if c.Request().Method != "POST" {
		return c.JSON(http.StatusMethodNotAllowed, echo.Map{"error": "Method not allowed"})
	}

	rc := http.NewResponseController(c.Response())
	_ = rc.SetWriteDeadline(time.Now().Add(30 * time.Minute))

	// 2. Limit request body size to prevent server exhaustion
	c.Request().Body = http.MaxBytesReader(c.Response(), c.Request().Body, MAX_UPLOAD_SIZE)
	if err := c.Request().ParseMultipartForm(MAX_UPLOAD_SIZE); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "File too large"})
	}

	// 3. Retrieve the file from the "video" form key
	file, handler, err := c.Request().FormFile("video")
	if err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "Error retrieving the file"})
	}
	defer file.Close()

	// 4. Validate file extension (basic check)
	if filepath.Ext(handler.Filename) != ".mp4" {
		return c.JSON(http.StatusUnsupportedMediaType, echo.Map{"error": "Only .mp4 files are allowed"})
	}

	// 5. Validate file content type (robust check)
	buff := make([]byte, 512)
	_, err = file.Read(buff)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": err.Error()})
	}

	filetype := http.DetectContentType(buff)
	if filetype != "video/mp4" {
		return c.JSON(http.StatusUnsupportedMediaType, echo.Map{"error": "The provided file is not a valid MP4 video."})
	}

	// Reset the file pointer to the start so subsequent reads work
	_, err = file.Seek(0, io.SeekStart)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": err.Error()})
	}

	fmt.Printf("Uploaded File: %+v\n", handler.Filename)
	fmt.Printf("File Size: %+v\n", handler.Size)

	// 5. Create a temp file to save the uploaded content
	// This ensures it works on ephemeral filesystems (like Railway) without needing persistent storage
	// if we only need the file for processing.
	tmpFile, err := os.CreateTemp("", "video-*.mp4")
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to create temp file: " + err.Error()})
	}
	defer os.Remove(tmpFile.Name()) // Clean up temp file
	defer tmpFile.Close()

	// 6. Copy the uploaded file to the destination
	if _, err := io.Copy(tmpFile, file); err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to save temp file: " + err.Error()})
	}

	// Ensure file is flushed and closed before reading/uploading (though UploadFromPath should handle it if path is valid)
	// Actually UploadFromPath takes a path, so we just need the name.
	// Sync to ensure all data is written to disk
	if err := tmpFile.Sync(); err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to sync temp file: " + err.Error()})
	}
	// Close it now so other processes can access it if needed (though on linux it's fine)
	tmpFile.Close()

	res, err := h.svc.UploadVideo(c.Request().Context(), tmpFile.Name(), "video/mp4")
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, videoassessment.VideoAssessmentResponse{
		FileName:   handler.Filename, // Return original filename to user
		Assessment: res.Assessment,
	})
}
