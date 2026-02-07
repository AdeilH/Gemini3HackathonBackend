package videoassessment

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	"google.golang.org/genai"
)

type Config struct {
	PostgresDSN   string
	Now           func() time.Time
	GeminiAPIKey  string
	GeminiBaseURL string
	GeminiModel   string
	db            *sql.DB
}

// Service provides AI API proxy functionality.
type Service struct {
	BaseURL string
	ApiKey  string
	Model   string
	db      *sql.DB
}

type VideoAssessmentResponse struct {
	FileName   string `json:"file_name"`
	Assessment string `json:"assessment"`
}

// NewService creates a new AI service with the given base URL, API key, and realtime API key.
func NewService(cfg Config, db *sql.DB) *Service {
	return &Service{
		BaseURL: cfg.GeminiBaseURL,
		ApiKey:  cfg.GeminiAPIKey,
		Model:   cfg.GeminiModel,
		db:      db,
	}
}

func (s *Service) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Service) UploadVideo(ctx context.Context, filePath string, mimeType string) (*VideoAssessmentResponse, error) {
	// google gemini client
	client, err := genai.NewClient(ctx, nil)
	if err != nil {
		log.Printf("Error creating Gemini client: %v", err)
		return nil, err
	}

	systemPrompt := `
	ROLE: You are "Visionary," an elite, multi-disciplinary performance coach with the eyes of a hawk.
	You possess the combined knowledge of a biomechanics expert, a TED talk curator, and a professional scout.
	Your goal is to analyze user-uploaded videos frame-by-frame to identify subtle mechanical flaws, missed opportunities, or excellence.
s
ANALYSIS PROTOCOL:
1. DETECT CONTEXT: Immediately identify the activity (e.g., "Cricket Cover Drive," "Startup Pitch," "Yoga Asana," "Guitar Solo").
2. TEMPORAL SCAN: You generally refuse to give vague advice. You MUST cite specific timestamps (e.g., "At 0:04, your elbow drops...") to prove you watched the video.
3. CAUSE & EFFECT: Do not just identify the mistake; explain the mechanical root cause. (e.g., "You missed the ball because your front foot wasn't planted at 0:02, limiting your reach.")

DOMAIN-SPECIFIC INSTRUCTIONS:
- IF SPORTS: Focus on biomechanics, center of gravity, torque, and follow-through. Compare their form to elite standards.
- IF SPEAKING: Focus on micro-expressions, tonal variance, pacing (words per minute), and "filler word" frequency. Analyze confidence vs. anxiety signals.
- IF MUSIC/SKILL: Focus on finger placement, rhythm consistency, and economy of motion.

OUTPUT FORMAT (Markdown):
## 🎯 Activity Detected: [Activity Name]
**Rating:** [1-10 Scale]

### 🔍 Critical Analysis
| Timestamp | Observation | Correction |
| :--- | :--- | :--- |
| [00:00] | [What happened] | [Specific fix] |

### 🚀 The "1%" Improvement
[One single, high-impact change they should make immediately to see results.]

### 💡 Coach's Vibe Check
[A 1-sentence motivational summary of their performance energy.]`

	fmt.Println("Uploading video...")
	file, err := client.Files.UploadFromPath(ctx, filePath, &genai.UploadFileConfig{
		MIMEType: mimeType,
	})
	if err != nil {
		log.Printf("Error uploading file to Gemini: %v", err)
		return nil, err
	}
	defer func() {
		// Clean up the file on Gemini's side when done (or keep it if needed, but best practice to delete)
		// For now we'll delete it to save storage on Gemini side
		if _, err := client.Files.Delete(ctx, file.Name, nil); err != nil {
			log.Printf("Failed to delete file from Gemini: %v", err)
		}
	}()

	fmt.Print("Processing video...")
	for {
		f, err := client.Files.Get(ctx, file.Name, nil)
		if err != nil {
			log.Printf("Error getting file status: %v", err)
			return nil, err
		}
		if f.State == "ACTIVE" {
			break
		}
		if f.State == "FAILED" {
			log.Println("Video processing failed")
			return nil, fmt.Errorf("video processing failed")
		}
		fmt.Print(".")
		time.Sleep(2 * time.Second)
	}
	fmt.Println("\nVideo is ready!")

	parts := []*genai.Part{
		{
			FileData: &genai.FileData{
				FileURI:  file.URI,
				MIMEType: file.MIMEType,
			},
		},
		{
			Text: systemPrompt,
		},
	}

	genAIVideo := []*genai.Content{
		{
			Parts: parts,
		},
	}

	genAIPrompt := genai.Content{
		Parts: []*genai.Part{
			{
				Text: systemPrompt,
			},
		},
	}

	config := genai.GenerateContentConfig{
		SystemInstruction: &genAIPrompt,
		ThinkingConfig: &genai.ThinkingConfig{
			ThinkingLevel: genai.ThinkingLevelLow,
		},
	}

	resp, err := client.Models.GenerateContent(
		ctx,
		s.Model,
		genAIVideo,
		&config,
	)
	if err != nil {
		log.Printf("Error generating content: %v", err)
		return nil, err
	}

	if len(resp.Candidates) == 0 || len(resp.Candidates[0].Content.Parts) == 0 {
		return nil, fmt.Errorf("no content generated")
	}

	generatedText := ""
	for _, part := range resp.Candidates[0].Content.Parts {
		generatedText += part.Text
	}

	fmt.Println(generatedText)
	return &VideoAssessmentResponse{FileName: filePath, Assessment: generatedText}, nil
}
