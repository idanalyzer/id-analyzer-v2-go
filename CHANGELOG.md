# Changelog

## 1.0.0 (2026-06-03)

Initial release of the official ID Analyzer **API v2** Go SDK.

- Full v2 surface: Scanner (scan / quickscan / veryquickscan), Biometric
  (face / liveness), AML (search / searchV3), Contract (generate + template CRUD),
  Transaction (get / list / update / delete / export / image+file vault), Docupass
  (create / list / get / delete), Profile (KYC profile CRUD + export), Webhook
  (list / resend / delete), Account (myaccount).
- Targets the load-balanced `api2.idanalyzer.com` (US, default) /
  `api2-eu.idanalyzer.com` (EU); region via `IDANALYZER_REGION` or `WithRegion`.
- Standard library only — no third-party dependencies.
- Module path `github.com/idanalyzer/id-analyzer-v2-go` (replaces the unofficial
  v1 Go SDK fork path).
