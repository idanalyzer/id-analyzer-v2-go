# ID Analyzer Go SDK — Identity Verification, KYC, Document & Biometric API

[![Go Reference](https://pkg.go.dev/badge/github.com/idanalyzer/id-analyzer-v2-go.svg)](https://pkg.go.dev/github.com/idanalyzer/id-analyzer-v2-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/idanalyzer/id-analyzer-v2-go)](https://goreportcard.com/report/github.com/idanalyzer/id-analyzer-v2-go)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Official Go client library for the **[ID Analyzer](https://www.idanalyzer.com) API v2** — automate identity document verification, KYC onboarding and biometric checks in minutes. Standard-library only, no third-party dependencies.

Scan and authenticate **passports, driver's licenses, ID cards, visas and residence permits from 190+ countries**, run **1:1 face match and liveness detection**, screen against **AML / PEP / sanctions** watchlists, and onboard users remotely with **DocuPass** hosted verification & e-signature.

- 🌐 **Website:** [www.idanalyzer.com](https://www.idanalyzer.com)
- 📚 **Developer docs & API reference:** [developer.idanalyzer.com](https://developer.idanalyzer.com/help)
- 📖 **Full SDK class reference (auto-generated):** [https://pkg.go.dev/github.com/idanalyzer/id-analyzer-v2-go](https://pkg.go.dev/github.com/idanalyzer/id-analyzer-v2-go)
- 🔑 **Get your API key:** [portal2.idanalyzer.com](https://portal2.idanalyzer.com)
- 💬 **Support:** support@idanalyzer.com

## Features

- **Document OCR & authentication** — passport, driver's license, ID card, visa & residence-permit recognition from 190+ countries, including MRZ and PDF417 / AAMVA barcode parsing.
- **Biometric verification** — 1:1 face match and liveness / presentation-attack detection.
- **AML screening** — PEP, sanctions, watchlist and adverse-media checks.
- **DocuPass** — hosted, no-code remote identity verification, KYC/AML onboarding and legally-binding e-signature.
- **KYC profiles, transaction vault, contract generation and webhooks.**
- **US & EU data-residency regions.**

> ⚠️ Never embed your API key in client-side apps (mobile, browser JS). Call the API from your server.

## Installation

```bash
go get github.com/idanalyzer/id-analyzer-v2-go
```

Requires Go 1.22+.

## Authentication & region

Pass your API key to `NewClient`, or set the `IDANALYZER_KEY` environment variable. The SDK targets the US endpoint (`https://api2.idanalyzer.com`) by default; select the EU endpoint with `IDANALYZER_REGION=eu` or `idanalyzer.WithRegion("eu")`. For on-premise ID Fort, use `idanalyzer.WithBaseURL("https://your-host")`.

## Quick start

```go
package main

import (
	"fmt"
	"log"

	idanalyzer "github.com/idanalyzer/id-analyzer-v2-go"
)

func main() {
	client, err := idanalyzer.NewClient("YOUR_API_KEY")
	if err != nil {
		log.Fatal(err)
	}

	profile := idanalyzer.NewProfile(idanalyzer.SecurityMedium)
	result, err := client.Scanner.Scan(idanalyzer.ScanRequest{
		DocumentFront: "id_front.jpg",
		Face:          "selfie.jpg",
		Profile:       profile,
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(result["decision"]) // accept / review / reject
}
```

## Examples

```go
// AML / PEP / sanctions screening
client.AML.Search(idanalyzer.AMLSearchRequest{Name: "John Smith", Country: "US"}) // POST /aml
client.AML.SearchV3("John Smith", "", 10, 1)                                       // POST /amlv3

// KYB — business verification
// Verify a business from its registration/incorporation document: extract
// details, check official company registries, screen against sanctions/PEP,
// and return directors/owners to verify.
client.KYB.Verify(idanalyzer.KYBVerifyRequest{Document: "registration.jpg"})                       // document only
client.KYB.Verify(idanalyzer.KYBVerifyRequest{Document: "registration.jpg", Profile: "security_high"}) // with a KYC profile

// DocuPass — hosted remote verification link
link, _ := client.Docupass.Create(idanalyzer.DocupassCreateRequest{Profile: "YOUR_PROFILE_ID"})
fmt.Println(link["url"])
```

See [`example/main.go`](example/main.go) for more.

## API coverage

The SDK wraps the complete ID Analyzer API v2 surface via service fields on the client:

| Service | Methods |
|---|---|
| `client.Scanner` | `Scan`, `QuickScan`, `VeryQuickScan` |
| `client.Biometric` | `VerifyFace`, `VerifyLiveness` |
| `client.AML` | `Search` (`/aml`), `SearchV3` (`/amlv3`) |
| `client.KYB` | `Verify` (`/kyb`) |
| `client.Contract` | `Generate` + template CRUD |
| `client.Transaction` | `Get`, `List`, `Update`, `Delete`, `Export`, `SaveImage`, `SaveFile` |
| `client.Docupass` | `Create`, `List`, `Get`, `Delete` |
| `client.Profile` | KYC profile `Create` / `List` / `Get` / `Update` / `Delete` / `Export` |
| `client.Webhook` | `List`, `Resend`, `Delete` |
| `client.Account` | `Get` |

## Resources

- [ID Analyzer website](https://www.idanalyzer.com)
- [Developer documentation & API reference](https://developer.idanalyzer.com/help)
- [Go SDK guide](https://developer.idanalyzer.com/help/go)
- [Dashboard — get your API key](https://portal2.idanalyzer.com)

## Other ID Analyzer SDKs

[PHP](https://github.com/idanalyzer/id-analyzer-v2-php) · [Python](https://github.com/idanalyzer/id-analyzer-v2-python) · [Node.js](https://github.com/idanalyzer/id-analyzer-v2-nodejs) · [.NET](https://github.com/idanalyzer/id-analyzer-v2-dotnet) · [Java](https://github.com/idanalyzer/id-analyzer-v2-java) · [Go](https://github.com/idanalyzer/id-analyzer-v2-go)

## License

MIT © [ID Analyzer](https://www.idanalyzer.com) — see [LICENSE](LICENSE).
