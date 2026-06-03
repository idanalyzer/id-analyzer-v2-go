# ID Analyzer Go SDK (API v2)

Official Go client library for the [ID Analyzer API v2](https://www.idanalyzer.com) —
worldwide passport, driver license and ID card scanning, biometric face/liveness
verification, AML/PEP screening, DocuPass remote verification & e-signature, KYC
profile management and contract generation.

It targets the load-balanced `api2.idanalyzer.com` fleet (US, default) or
`api2-eu.idanalyzer.com` (EU). Standard library only — no third-party dependencies.

> Replaces the legacy v1 Go SDK. New projects should use this module.

## Installation
```shell
go get github.com/idanalyzer/id-analyzer-v2-go
```

## Base URL / Region
By default the SDK targets the US fleet. Select EU either via the environment
variable `IDANALYZER_REGION=eu` or with the `WithRegion` option:

```go
client, _ := idanalyzer.NewClient("YOUR_API_KEY", idanalyzer.WithRegion("eu"))
```

For an on-premise ID Fort host, use `idanalyzer.WithBaseURL("https://your-host")`.
The API key also falls back to the `IDANALYZER_KEY` environment variable.

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
	fmt.Println(result["decision"])
}
```

## API Coverage
The SDK exposes the full ID Analyzer API v2 surface via service fields on the client:

- **client.Scanner** — `Scan`, `QuickScan`, `VeryQuickScan`
- **client.Biometric** — `VerifyFace`, `VerifyLiveness`
- **client.AML** — `Search` (`/aml`), `SearchV3` (`/amlv3`)
- **client.Contract** — `Generate` + template CRUD
- **client.Transaction** — `Get`, `List`, `Update`, `Delete`, `Export`, `SaveImage`, `SaveFile`
- **client.Docupass** — `Create`, `List`, `Get`, `Delete`
- **client.Profile** — KYC profile `Create`/`List`/`Get`/`Update`/`Delete`/`Export`
- **client.Webhook** — `List`, `Resend`, `Delete`
- **client.Account** — `Get` (`/myaccount`)

## Errors
API-level errors are returned as `*idanalyzer.APIError` (with `Code` and `Message`);
invalid client-side arguments are returned as `*idanalyzer.InvalidArgumentError`.

## Documentation
Guide: [developer.idanalyzer.com/help/go](https://developer.idanalyzer.com/help/go) · Knowledge base: [developer.idanalyzer.com/help](https://developer.idanalyzer.com/help)

## License
MIT
