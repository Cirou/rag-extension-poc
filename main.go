package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"io"
	"strings"
	"log"
	"path/filepath"
	"archive/zip"
	"bytes"

	"github.com/copilot-extensions/rag-extension/agent"
	"github.com/copilot-extensions/rag-extension/config"
	"github.com/copilot-extensions/rag-extension/oauth"

)

func main() {
	
	if err := convertDocx(); err != nil {
		log.Fatalf("Errore durante la conversione: %v", err)
	}

	if err := run(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func run() error {
	pubKey, err := fetchPublicKey()
	if err != nil {
		return fmt.Errorf("failed to fetch public key: %w", err)
	}

	config, err := config.New()
	if err != nil {
		return fmt.Errorf("error fetching config: %w", err)
	}

	me, err := url.Parse(config.FQDN)
	if err != nil {
		return fmt.Errorf("unable to parse HOST environment variable: %w", err)
	}

	me.Path = "auth/callback"

	oauthService := oauth.NewService(config.ClientID, config.ClientSecret, me.String())
	http.HandleFunc("/auth/authorization", oauthService.PreAuth)
	http.HandleFunc("/auth/callback", oauthService.PostAuth)

	agentService := agent.NewService(pubKey)

	http.HandleFunc("/agent", agentService.ChatCompletion)

	fmt.Println("Listening on port", config.Port)
	return http.ListenAndServe(":"+config.Port, nil)
}

// fetchPublicKey fetches the keys used to sign messages from copilot.  Checking
// the signature with one of these keys verifies that the request to the
// completions API comes from GitHub and not elsewhere on the internet.
func fetchPublicKey() (*ecdsa.PublicKey, error) {
	
	// URL dell'API di GitHub
	url := "https://api.github.com/meta/public_keys/copilot_api"

	// Crea la richiesta
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Aggiungi l'intestazione User-Agent
	req.Header.Set("User-Agent", "rag-extension-poc/1.0")

	token := os.Getenv("GITHUB_TOKEN") // Assicurati di configurare questa variabile
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	// Invia la richiesta
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch public key: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch public key: %s", resp.Status)
	}

	var respBody struct {
		PublicKeys []struct {
			Key       string `json:"key"`
			IsCurrent bool   `json:"is_current"`
		} `json:"public_keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	var rawKey string
	for _, pk := range respBody.PublicKeys {
		if pk.IsCurrent {
			rawKey = pk.Key
			break
		}
	}
	if rawKey == "" {
		return nil, fmt.Errorf("could not find current public key")
	}

	pubPemStr := strings.ReplaceAll(rawKey, "\\n", "\n")
	// Decode the Public Key
	block, _ := pem.Decode([]byte(pubPemStr))
	if block == nil {
		return nil, fmt.Errorf("error parsing PEM block with GitHub public key")
	}

	// Create our ECDSA Public Key
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	// Because of documentation, we know it's a *ecdsa.PublicKey
	ecdsaKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("GitHub key is not ECDSA")
	}

	return ecdsaKey, nil
}

// convertDocx legge i file .docx, estrae il contenuto testuale e lo salva in .md
func convertDocx() error {
	inputDir := "./documents"
	outputDir := "./data"
	processedDir := filepath.Join(inputDir, "processed")

	// Crea cartelle necessarie
	if err := os.MkdirAll(outputDir, os.ModePerm); err != nil {
		return fmt.Errorf("impossibile creare la cartella di output: %w", err)
	}
	if err := os.MkdirAll(processedDir, os.ModePerm); err != nil {
		return fmt.Errorf("impossibile creare la cartella processed: %w", err)
	}

	// Leggi i file nella cartella input
	files, err := os.ReadDir(inputDir)
	if err != nil {
		return fmt.Errorf("impossibile leggere la cartella %s: %w", inputDir, err)
	}

	for _, file := range files {
		// Processa solo file con estensione .docx
		if filepath.Ext(file.Name()) != ".docx" {
			continue
		}

		inputFilePath := filepath.Join(inputDir, file.Name())
		fmt.Printf("Elaborazione del file: %s\n", inputFilePath)

		// Estrai il contenuto testuale dal file .docx
		text, err := extractTextFromDocx(inputFilePath)
		if err != nil {
			log.Printf("Errore nell'elaborazione del file %s: %v", inputFilePath, err)
			continue
		}

		// Scrivi il testo estratto in un file .md
		outputFileName := strings.TrimSuffix(file.Name(), ".docx") + ".md"
		outputFilePath := filepath.Join(outputDir, outputFileName)
		err = os.WriteFile(outputFilePath, []byte(text), 0644)
		if err != nil {
			log.Printf("Errore nella scrittura del file %s: %v", outputFilePath, err)
			continue
		}

		// Sposta il file originale nella cartella processed
		processedFilePath := filepath.Join(processedDir, file.Name())
		err = os.Rename(inputFilePath, processedFilePath)
		if err != nil {
			log.Printf("Errore nello spostamento del file %s nella cartella processed: %v", inputFilePath, err)
			continue
		}

		fmt.Printf("File convertito e salvato: %s\n", outputFilePath)
	}

	return nil
}

// extractTextFromDocx estrae il contenuto testuale da un file .docx
func extractTextFromDocx(filePath string) (string, error) {
	// Apri il file .docx come archivio ZIP
	reader, err := zip.OpenReader(filePath)
	if err != nil {
		return "", fmt.Errorf("impossibile aprire il file .docx: %w", err)
	}
	defer reader.Close()

	var documentXML *zip.File
	for _, file := range reader.File {
		if file.Name == "word/document.xml" {
			documentXML = file
			break
		}
	}

	if documentXML == nil {
		return "", fmt.Errorf("document.xml non trovato nel file .docx")
	}

	// Leggi il contenuto di document.xml
	rc, err := documentXML.Open()
	if err != nil {
		return "", fmt.Errorf("impossibile aprire document.xml: %w", err)
	}
	defer rc.Close()

	// Estrai il testo eliminando i tag XML
	var buffer bytes.Buffer
	_, err = io.Copy(&buffer, rc)
	if err != nil {
		return "", fmt.Errorf("impossibile leggere document.xml: %w", err)
	}

	// Rimuovi i tag XML
	text := stripXMLTags(buffer.String())
	return text, nil
}

// stripXMLTags rimuove i tag XML da una stringa
func stripXMLTags(input string) string {
	var output strings.Builder
	inTag := false

	for _, char := range input {
		if char == '<' {
			inTag = true
			continue
		}
		if char == '>' {
			inTag = false
			continue
		}
		if !inTag {
			output.WriteRune(char)
		}
	}

	return strings.TrimSpace(output.String())
}