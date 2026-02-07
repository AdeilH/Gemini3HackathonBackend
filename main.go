// package main

// import (
// 	"context"
// 	"fmt"
// 	"io"
// 	"log"
// 	"net/http"
// 	"os"
// 	"path/filepath"
// 	"time"

// 	"google.golang.org/genai"
// )

// const MAX_UPLOAD_SIZE = 100 * 1024 * 1024

// func uploadHandler(w http.ResponseWriter, r *http.Request) {
// 	// 1. Set CORS (if your frontend is on a different port/domain)
// 	w.Header().Set("Access-Control-Allow-Origin", "*")
// 	if r.Method == "OPTIONS" {
// 		return
// 	}

// 	if r.Method != "POST" {
// 		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
// 		return
// 	}

// 	// 2. Limit request body size to prevent server exhaustion
// 	r.Body = http.MaxBytesReader(w, r.Body, MAX_UPLOAD_SIZE)
// 	if err := r.ParseMultipartForm(MAX_UPLOAD_SIZE); err != nil {
// 		http.Error(w, "File too large", http.StatusBadRequest)
// 		return
// 	}

// 	// 3. Retrieve the file from the "video" form key
// 	file, handler, err := r.FormFile("video")
// 	if err != nil {
// 		http.Error(w, "Error retrieving the file", http.StatusBadRequest)
// 		return
// 	}
// 	defer file.Close()

// 	// 4. Validate file extension (basic check)
// 	if filepath.Ext(handler.Filename) != ".mp4" {
// 		http.Error(w, "Only .mp4 files are allowed", http.StatusUnsupportedMediaType)
// 		return
// 	}

// 	// 5. Validate file content type (robust check)
// 	buff := make([]byte, 512)
// 	_, err = file.Read(buff)
// 	if err != nil {
// 		http.Error(w, err.Error(), http.StatusInternalServerError)
// 		return
// 	}

// 	filetype := http.DetectContentType(buff)
// 	if filetype != "video/mp4" {
// 		http.Error(w, "The provided file is not a valid MP4 video.", http.StatusBadRequest)
// 		return
// 	}

// 	// Reset the file pointer to the start so subsequent reads work
// 	_, err = file.Seek(0, io.SeekStart)
// 	if err != nil {
// 		http.Error(w, err.Error(), http.StatusInternalServerError)
// 		return
// 	}

// 	fmt.Printf("Uploaded File: %+v\n", handler.Filename)
// 	fmt.Printf("File Size: %+v\n", handler.Size)

// 	// 5. Create a local file to save the uploaded content
// 	// Ensure the "uploads" directory exists first
// 	os.MkdirAll("./uploads", os.ModePerm)
// 	dst, err := os.Create(filepath.Join("./uploads", handler.Filename))
// 	if err != nil {
// 		http.Error(w, err.Error(), http.StatusInternalServerError)
// 		return
// 	}
// 	defer dst.Close()

// 	// 6. Copy the uploaded file to the destination
// 	if _, err := io.Copy(dst, file); err != nil {
// 		http.Error(w, err.Error(), http.StatusInternalServerError)
// 		return
// 	}

// 	fmt.Fprintf(w, "Successfully Uploaded: %s", handler.Filename)

// 	response := assessVideo(handler.Filename)
// 	fmt.Println(response.Text())
// 	fmt.Println(response.Candidates[0].Content.Parts[0].Text)
// }

// // --- Handler ---
// func main() {

// 	// err := godotenv.Load(".env")
// 	// if err != nil {
// 	// 	log.Fatal("Error loading .env file:", err)
// 	// }
// 	// Get port from environment
// 	port := os.Getenv("PORT")
// 	if port == "" {
// 		port = "8080"
// 	}

// 	http.HandleFunc("/upload", uploadHandler)

// 	fmt.Println("Server started on :" + port)
// 	http.ListenAndServe(":"+port, nil)

// }

// func assessVideo(fileName string) *genai.GenerateContentResponse {
// 	ctx := context.Background()

// 	// google gemini client
// 	client, err := genai.NewClient(ctx, nil)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	systemPrompt := `
// 	ROLE: You are "Visionary," an elite, multi-disciplinary performance coach with the eyes of a hawk.
// 	You possess the combined knowledge of a biomechanics expert, a TED talk curator, and a professional scout.
// 	Your goal is to analyze user-uploaded videos frame-by-frame to identify subtle mechanical flaws, missed opportunities, or excellence.
// s
// ANALYSIS PROTOCOL:
// 1. DETECT CONTEXT: Immediately identify the activity (e.g., "Cricket Cover Drive," "Startup Pitch," "Yoga Asana," "Guitar Solo").
// 2. TEMPORAL SCAN: You generally refuse to give vague advice. You MUST cite specific timestamps (e.g., "At 0:04, your elbow drops...") to prove you watched the video.
// 3. CAUSE & EFFECT: Do not just identify the mistake; explain the mechanical root cause. (e.g., "You missed the ball because your front foot wasn't planted at 0:02, limiting your reach.")

// DOMAIN-SPECIFIC INSTRUCTIONS:
// - IF SPORTS: Focus on biomechanics, center of gravity, torque, and follow-through. Compare their form to elite standards.
// - IF SPEAKING: Focus on micro-expressions, tonal variance, pacing (words per minute), and "filler word" frequency. Analyze confidence vs. anxiety signals.
// - IF MUSIC/SKILL: Focus on finger placement, rhythm consistency, and economy of motion.

// OUTPUT FORMAT (Markdown):
// ## 🎯 Activity Detected: [Activity Name]
// **Rating:** [1-10 Scale]

// ### 🔍 Critical Analysis
// | Timestamp | Observation | Correction |
// | :--- | :--- | :--- |
// | [00:00] | [What happened] | [Specific fix] |

// ### 🚀 The "1%" Improvement
// [One single, high-impact change they should make immediately to see results.]

// ### 💡 Coach's Vibe Check
// [A 1-sentence motivational summary of their performance energy.]`

// 	sanitizedFileName := "./uploads/" + fileName
// 	fmt.Println("Uploading video...")
// 	file, err := client.Files.UploadFromPath(ctx, sanitizedFileName, &genai.UploadFileConfig{
// 		MIMEType: "video/mp4",
// 	})
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	// defer func() {
// 	// 	client.Files.Delete(ctx, file.Name, &genai.DeleteFileConfig{
// 	// 		MIMEType: "video/mp4",
// 	// 	})
// 	// }()

// 	fmt.Print("Processing video...")
// 	for {
// 		f, err := client.Files.Get(ctx, file.Name, nil)
// 		if err != nil {
// 			log.Fatal(err)
// 		}
// 		if f.State == "ACTIVE" {
// 			break
// 		}
// 		if f.State == "FAILED" {
// 			log.Fatal("Video processing failed")
// 		}
// 		fmt.Print(".")
// 		time.Sleep(2 * time.Second)
// 	}
// 	fmt.Println("\nVideo is ready!")

// 	parts := []*genai.Part{
// 		{
// 			FileData: &genai.FileData{
// 				FileURI:  file.URI,
// 				MIMEType: file.MIMEType,
// 			},
// 		},
// 		{
// 			Text: systemPrompt,
// 		},
// 	}

// 	genAIVideo := []*genai.Content{
// 		{
// 			Parts: parts,
// 		},
// 	}

// 	genAIPrompt := genai.Content{
// 		Parts: []*genai.Part{
// 			{
// 				Text: systemPrompt,
// 			},
// 		},
// 	}

// 	config := genai.GenerateContentConfig{
// 		SystemInstruction: &genAIPrompt,
// 		ThinkingConfig: &genai.ThinkingConfig{
// 			ThinkingLevel: genai.ThinkingLevelLow,
// 		},
// 	}

// 	resp, err := client.Models.GenerateContent(
// 		ctx,
// 		"gemini-3-flash-preview",
// 		genAIVideo,
// 		&config,
// 	)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	return resp
// }

package main

import "log"

func main() {
	if err := runServer(); err != nil {
		log.Fatal(err)
	}
}
