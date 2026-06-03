//go:build ignore

// Example usage of the ID Analyzer API v2 Go SDK.
// Run with: IDANALYZER_KEY=your_key go run main.go
package main

import (
	"fmt"
	"log"

	idanalyzer "github.com/idanalyzer/id-analyzer-v2-go"
)

func main() {
	// API key from the IDANALYZER_KEY env var; region from IDANALYZER_REGION (default "us").
	// Use idanalyzer.WithRegion("eu") for the EU endpoint.
	client, err := idanalyzer.NewClient("")
	if err != nil {
		log.Fatal(err)
	}

	// Standard scan.
	profile := idanalyzer.NewProfile(idanalyzer.SecurityMedium)
	scan, err := client.Scanner.Scan(idanalyzer.ScanRequest{
		DocumentFront: "id_front.jpg",
		Face:          "selfie.jpg",
		Profile:       profile,
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("scan decision:", scan["decision"])

	// Quick OCR-only scan.
	if _, err := client.Scanner.QuickScan("id_front.jpg", "", true); err != nil {
		log.Fatal(err)
	}

	// AML screening.
	if _, err := client.AML.Search(idanalyzer.AMLSearchRequest{Name: "John Smith", Country: "US"}); err != nil {
		log.Fatal(err)
	}
	if _, err := client.AML.SearchV3("John Smith", "", 10, 1); err != nil {
		log.Fatal(err)
	}

	// Account quota.
	acct, err := client.Account.Get()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("account:", acct)
}
