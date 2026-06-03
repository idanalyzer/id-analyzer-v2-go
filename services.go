package idanalyzer

import (
	"net/http"
	"net/url"
	"strconv"
)

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------

// ScannerService provides identity document scanning operations. Access it via
// Client.Scanner.
type ScannerService struct{ client *Client }

// ScanRequest holds the inputs and options for a standard scan (POST /scan).
// DocumentFront and Profile are required; all other fields are optional.
type ScanRequest struct {
	DocumentFront string   // file path, base64, URL, or "ref:" cache reference (required)
	DocumentBack  string   // back of the document, same accepted forms as DocumentFront
	Face          string   // selfie photo for biometric verification
	FaceVideo     string   // selfie video for biometric verification (used when Face is empty)
	Profile       *Profile // KYC profile to apply (required; build with NewProfile)

	RestrictCountry      string         // accept only these issuing countries (ISO Alpha-2, comma separated)
	RestrictState        string         // accept only these issuing states (comma separated)
	RestrictType         string         // accept only these document types (e.g. "PD")
	VerifyName           string         // assert the holder's name matches this value
	VerifyDob            string         // assert the date of birth (YYYY/MM/DD)
	VerifyAge            string         // assert the age falls in this range, e.g. "18-40"
	VerifyAddress        string         // assert the holder's address matches this value
	VerifyPostcode       string         // assert the postcode matches this value
	VerifyDocumentNumber string         // assert the document number matches this value
	ContractGenerate     string         // contract template ID to fill from the scan result
	ContractFormat       string         // generated contract format (e.g. "PDF")
	ContractPrefill      map[string]any // extra key/value data merged into the contract
	IP                   string         // end-user IP address, for geolocation/risk signals
	CustomData           string         // arbitrary string echoed back on the transaction
}

func putStr(m map[string]any, k, v string) {
	if v != "" {
		m[k] = v
	}
}

// Scan initiates a full identity document scan and optional biometric
// verification. The request's DocumentFront and Profile fields are required;
// it returns the decoded JSON response as a map, or an error (including
// *InvalidArgumentError for missing inputs and *APIError for an API-reported
// failure).
func (s *ScannerService) Scan(req ScanRequest) (map[string]any, error) {
	if req.Profile == nil {
		return nil, invalid("Profile is required (use NewProfile)")
	}
	if req.DocumentFront == "" {
		return nil, invalid("DocumentFront is required")
	}
	payload := map[string]any{"profile": req.Profile.ID}
	if len(req.Profile.Override) > 0 {
		payload["profileOverride"] = req.Profile.Override
	}

	doc, err := ParseInput(req.DocumentFront, true)
	if err != nil {
		return nil, err
	}
	payload["document"] = doc
	if req.DocumentBack != "" {
		if payload["documentBack"], err = ParseInput(req.DocumentBack, true); err != nil {
			return nil, err
		}
	}
	if req.Face != "" {
		if payload["face"], err = ParseInput(req.Face, true); err != nil {
			return nil, err
		}
	} else if req.FaceVideo != "" {
		if payload["faceVideo"], err = ParseInput(req.FaceVideo, false); err != nil {
			return nil, err
		}
	}

	putStr(payload, "restrictCountry", req.RestrictCountry)
	putStr(payload, "restrictState", req.RestrictState)
	putStr(payload, "restrictType", req.RestrictType)
	putStr(payload, "verifyName", req.VerifyName)
	putStr(payload, "verifyDob", req.VerifyDob)
	putStr(payload, "verifyAge", req.VerifyAge)
	putStr(payload, "verifyAddress", req.VerifyAddress)
	putStr(payload, "verifyPostcode", req.VerifyPostcode)
	putStr(payload, "verifyDocumentNumber", req.VerifyDocumentNumber)
	putStr(payload, "contractGenerate", req.ContractGenerate)
	putStr(payload, "contractFormat", req.ContractFormat)
	putStr(payload, "ip", req.IP)
	putStr(payload, "customData", req.CustomData)
	if len(req.ContractPrefill) > 0 {
		payload["contractPrefill"] = req.ContractPrefill
	}

	return s.client.doJSON(http.MethodPost, "scan", payload, nil)
}

// QuickScan initiates a quick OCR-only scan. documentFront (required) and
// documentBack accept a file path, base64 string or URL. When cacheImage is
// true the uploaded image is retained server-side so it can be reused via a
// "ref:" reference. It returns the decoded JSON response, or an error.
func (s *ScannerService) QuickScan(documentFront, documentBack string, cacheImage bool) (map[string]any, error) {
	return s.quick("quickscan", documentFront, documentBack, cacheImage)
}

// VeryQuickScan initiates a very fast OCR-only scan. Its parameters and return
// value match QuickScan; it trades accuracy for lower latency.
func (s *ScannerService) VeryQuickScan(documentFront, documentBack string, cacheImage bool) (map[string]any, error) {
	return s.quick("veryquickscan", documentFront, documentBack, cacheImage)
}

func (s *ScannerService) quick(uri, documentFront, documentBack string, cacheImage bool) (map[string]any, error) {
	if documentFront == "" {
		return nil, invalid("documentFront is required")
	}
	payload := map[string]any{"saveFile": cacheImage}
	doc, err := ParseInput(documentFront, false)
	if err != nil {
		return nil, err
	}
	payload["document"] = doc
	if documentBack != "" {
		if payload["documentBack"], err = ParseInput(documentBack, false); err != nil {
			return nil, err
		}
	}
	return s.client.doJSON(http.MethodPost, uri, payload, nil)
}

// ---------------------------------------------------------------------------
// Biometric
// ---------------------------------------------------------------------------

// BiometricService provides face matching and liveness operations. Access it
// via Client.Biometric.
type BiometricService struct{ client *Client }

// VerifyFace performs 1:1 face verification against a reference image
// (POST /face). profile (required) selects the KYC profile; referenceFaceImage
// (required) is the known face to match against; supply exactly one of
// facePhoto or faceVideo as the live capture to verify; customData is an
// optional string echoed on the transaction. It returns the decoded JSON
// response, or an error.
func (b *BiometricService) VerifyFace(profile *Profile, referenceFaceImage, facePhoto, faceVideo, customData string) (map[string]any, error) {
	if profile == nil {
		return nil, invalid("Profile is required")
	}
	if referenceFaceImage == "" {
		return nil, invalid("referenceFaceImage is required")
	}
	if facePhoto == "" && faceVideo == "" {
		return nil, invalid("a verification face photo or video is required")
	}
	payload := map[string]any{"profile": profile.ID}
	if len(profile.Override) > 0 {
		payload["profileOverride"] = profile.Override
	}
	var err error
	if payload["reference"], err = ParseInput(referenceFaceImage, true); err != nil {
		return nil, err
	}
	if facePhoto != "" {
		if payload["face"], err = ParseInput(facePhoto, true); err != nil {
			return nil, err
		}
	} else {
		if payload["faceVideo"], err = ParseInput(faceVideo, false); err != nil {
			return nil, err
		}
	}
	putStr(payload, "customData", customData)
	return b.client.doJSON(http.MethodPost, "face", payload, nil)
}

// VerifyLiveness performs a standalone liveness check (POST /liveness).
// profile (required) selects the KYC profile; supply exactly one of facePhoto
// or faceVideo as the live capture; customData is an optional string echoed on
// the transaction. It returns the decoded JSON response, or an error.
func (b *BiometricService) VerifyLiveness(profile *Profile, facePhoto, faceVideo, customData string) (map[string]any, error) {
	if profile == nil {
		return nil, invalid("Profile is required")
	}
	if facePhoto == "" && faceVideo == "" {
		return nil, invalid("a face photo or video is required")
	}
	payload := map[string]any{"profile": profile.ID}
	if len(profile.Override) > 0 {
		payload["profileOverride"] = profile.Override
	}
	var err error
	if facePhoto != "" {
		if payload["face"], err = ParseInput(facePhoto, true); err != nil {
			return nil, err
		}
	} else {
		if payload["faceVideo"], err = ParseInput(faceVideo, false); err != nil {
			return nil, err
		}
	}
	putStr(payload, "customData", customData)
	return b.client.doJSON(http.MethodPost, "liveness", payload, nil)
}

// ---------------------------------------------------------------------------
// AML
// ---------------------------------------------------------------------------

// AMLService provides anti-money-laundering / sanctions screening operations.
// Access it via Client.AML.
type AMLService struct{ client *Client }

// AMLSearchRequest holds parameters for an AML v1 search (POST /aml). Either
// Name or IDNumber must be set.
type AMLSearchRequest struct {
	Name      string   // full name of the person or entity to screen
	IDNumber  string   // government/registration ID number to screen
	Entity    int      // 0=Person, 1=Corporation/Legal Entity
	Country   string   // ISO Alpha-2 country to bias/limit the search
	Database  []string // specific watchlist databases to query (default: all)
	BirthYear string   // year of birth, to disambiguate matches
}

// Search screens a name or ID number against the AML watchlists (POST /aml).
// It returns the decoded JSON response, or an error.
func (a *AMLService) Search(req AMLSearchRequest) (map[string]any, error) {
	if req.Name == "" && req.IDNumber == "" {
		return nil, invalid("either Name or IDNumber is required")
	}
	payload := map[string]any{"entity": req.Entity}
	putStr(payload, "name", req.Name)
	putStr(payload, "idNumber", req.IDNumber)
	putStr(payload, "country", req.Country)
	putStr(payload, "birthYear", req.BirthYear)
	if len(req.Database) > 0 {
		payload["database"] = req.Database
	}
	return a.client.doJSON(http.MethodPost, "aml", payload, nil)
}

// SearchV3 screens against the AML v3 database (POST /amlv3). Provide either a
// free-text query (text) or a record id; limit caps the number of results
// (sent only when positive) and page selects the result page (1-based, sent
// only when positive). It returns the decoded JSON response, or an error.
func (a *AMLService) SearchV3(text, id string, limit, page int) (map[string]any, error) {
	if text == "" && id == "" {
		return nil, invalid("either text or id is required")
	}
	payload := map[string]any{}
	putStr(payload, "text", text)
	putStr(payload, "id", id)
	if limit > 0 {
		payload["limit"] = limit
	}
	if page > 0 {
		payload["page"] = page
	}
	return a.client.doJSON(http.MethodPost, "amlv3", payload, nil)
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

// ContractService provides contract/document template management and document
// generation. Access it via Client.Contract.
type ContractService struct{ client *Client }

// Generate generates a document from a template (POST /generate). templateID
// (required) names the template; format defaults to "PDF" when empty;
// transactionID optionally links the document to an existing transaction whose
// data prefills the template; fillData supplies additional key/value pairs. It
// returns the decoded JSON response, or an error.
func (c *ContractService) Generate(templateID, format, transactionID string, fillData map[string]any) (map[string]any, error) {
	if templateID == "" {
		return nil, invalid("templateID is required")
	}
	if format == "" {
		format = "PDF"
	}
	payload := map[string]any{"templateId": templateID, "format": format}
	putStr(payload, "transactionId", transactionID)
	if len(fillData) > 0 {
		payload["fillData"] = fillData
	}
	return c.client.doJSON(http.MethodPost, "generate", payload, nil)
}

// ListTemplate lists contract templates (GET /contract). order sets the sort
// direction (1 ascending, -1 descending), limit caps the page size, offset
// skips records for pagination, and filterTemplateID (when non-empty) returns
// only the matching template. It returns the decoded JSON response, or an
// error.
func (c *ContractService) ListTemplate(order, limit, offset int, filterTemplateID string) (map[string]any, error) {
	q := url.Values{}
	q.Set("order", strconv.Itoa(order))
	q.Set("limit", strconv.Itoa(limit))
	q.Set("offset", strconv.Itoa(offset))
	if filterTemplateID != "" {
		q.Set("templateId", filterTemplateID)
	}
	return c.client.doJSON(http.MethodGet, "contract", nil, q)
}

// GetTemplate retrieves a contract template by its templateID (required)
// (GET /contract/{id}). It returns the decoded JSON response, or an error.
func (c *ContractService) GetTemplate(templateID string) (map[string]any, error) {
	if templateID == "" {
		return nil, invalid("templateID is required")
	}
	return c.client.doJSON(http.MethodGet, "contract/"+templateID, nil, nil)
}

// CreateTemplate creates a contract template (POST /contract). name and
// content (the template HTML body) are required; orientation, timezone and
// font set the rendering options. It returns the decoded JSON response, or an
// error.
func (c *ContractService) CreateTemplate(name, content, orientation, timezone, font string) (map[string]any, error) {
	if name == "" {
		return nil, invalid("name is required")
	}
	if content == "" {
		return nil, invalid("content is required")
	}
	payload := map[string]any{"name": name, "content": content, "orientation": orientation, "timezone": timezone, "font": font}
	return c.client.doJSON(http.MethodPost, "contract", payload, nil)
}

// UpdateTemplate updates the contract template identified by templateID
// (required) (POST /contract/{id}). name, content, orientation, timezone and
// font replace the stored template's corresponding fields. It returns the
// decoded JSON response, or an error.
func (c *ContractService) UpdateTemplate(templateID, name, content, orientation, timezone, font string) (map[string]any, error) {
	if templateID == "" {
		return nil, invalid("templateID is required")
	}
	payload := map[string]any{"name": name, "content": content, "orientation": orientation, "timezone": timezone, "font": font}
	return c.client.doJSON(http.MethodPost, "contract/"+templateID, payload, nil)
}

// DeleteTemplate deletes the contract template identified by templateID
// (required) (DELETE /contract/{id}). It returns the decoded JSON response, or
// an error.
func (c *ContractService) DeleteTemplate(templateID string) (map[string]any, error) {
	if templateID == "" {
		return nil, invalid("templateID is required")
	}
	return c.client.doJSON(http.MethodDelete, "contract/"+templateID, nil, nil)
}

// ---------------------------------------------------------------------------
// Transaction
// ---------------------------------------------------------------------------

// TransactionService provides access to stored transaction records and the
// image/file vault. Access it via Client.Transaction.
type TransactionService struct{ client *Client }

// TransactionListOptions holds filters for listing/exporting transactions. The
// zero value is valid: Order defaults to -1 (descending) and Limit to 10.
type TransactionListOptions struct {
	Order            int    // sort direction: 1 ascending, -1 descending (default -1)
	Limit            int    // maximum records to return (default 10)
	Offset           int    // records to skip, for pagination
	CreatedAtMin     int    // earliest creation time, Unix seconds (0 = no bound)
	CreatedAtMax     int    // latest creation time, Unix seconds (0 = no bound)
	FilterCustomData string // match the transaction's customData field
	FilterDecision   string // match the decision: "accept", "review" or "reject"
	FilterDocupass   string // match the originating Docupass reference
	FilterProfileID  string // match the KYC profile ID used
}

// values renders the options into a url.Values query string, applying the
// Order/Limit defaults.
func (o TransactionListOptions) values() url.Values {
	q := url.Values{}
	order := o.Order
	if order == 0 {
		order = -1
	}
	limit := o.Limit
	if limit == 0 {
		limit = 10
	}
	q.Set("order", strconv.Itoa(order))
	q.Set("limit", strconv.Itoa(limit))
	q.Set("offset", strconv.Itoa(o.Offset))
	if o.CreatedAtMin > 0 {
		q.Set("createdAtMin", strconv.Itoa(o.CreatedAtMin))
	}
	if o.CreatedAtMax > 0 {
		q.Set("createdAtMax", strconv.Itoa(o.CreatedAtMax))
	}
	if o.FilterCustomData != "" {
		q.Set("customData", o.FilterCustomData)
	}
	if o.FilterDecision != "" {
		q.Set("decision", o.FilterDecision)
	}
	if o.FilterDocupass != "" {
		q.Set("docupass", o.FilterDocupass)
	}
	if o.FilterProfileID != "" {
		q.Set("profileId", o.FilterProfileID)
	}
	return q
}

// Get retrieves the single transaction identified by transactionID (required)
// (GET /transaction/{id}). It returns the decoded JSON response, or an error.
func (t *TransactionService) Get(transactionID string) (map[string]any, error) {
	if transactionID == "" {
		return nil, invalid("transactionID is required")
	}
	return t.client.doJSON(http.MethodGet, "transaction/"+transactionID, nil, nil)
}

// List retrieves transaction history filtered and paginated by opts
// (GET /transaction). It returns the decoded JSON response, or an error.
func (t *TransactionService) List(opts TransactionListOptions) (map[string]any, error) {
	return t.client.doJSON(http.MethodGet, "transaction", nil, opts.values())
}

// Update overrides the decision on the transaction identified by transactionID
// (required) (PATCH /transaction/{id}). decision must be one of "accept",
// "review" or "reject". It returns the decoded JSON response, or an error.
func (t *TransactionService) Update(transactionID, decision string) (map[string]any, error) {
	if transactionID == "" {
		return nil, invalid("transactionID is required")
	}
	if decision != "accept" && decision != "review" && decision != "reject" {
		return nil, invalid("decision should be one of accept, review, reject")
	}
	return t.client.doJSON(http.MethodPatch, "transaction/"+transactionID, map[string]any{"decision": decision}, nil)
}

// Delete deletes the transaction identified by transactionID (required)
// (DELETE /transaction/{id}). It returns the decoded JSON response, or an
// error.
func (t *TransactionService) Delete(transactionID string) (map[string]any, error) {
	if transactionID == "" {
		return nil, invalid("transactionID is required")
	}
	return t.client.doJSON(http.MethodDelete, "transaction/"+transactionID, nil, nil)
}

// SaveImage downloads the vault image identified by imageToken (required) and
// writes it to the local path dest (required) (GET /imagevault/{token}). It
// returns an error if the arguments are missing or the download fails.
func (t *TransactionService) SaveImage(imageToken, dest string) error {
	if imageToken == "" || dest == "" {
		return invalid("imageToken and dest are required")
	}
	return t.client.download("imagevault/"+imageToken, dest)
}

// SaveFile downloads the vault file named fileName (required) and writes it to
// the local path dest (required) (GET /filevault/{name}). It returns an error
// if the arguments are missing or the download fails.
func (t *TransactionService) SaveFile(fileName, dest string) error {
	if fileName == "" || dest == "" {
		return invalid("fileName and dest are required")
	}
	return t.client.download("filevault/"+fileName, dest)
}

// Export requests a transaction archive and downloads it to the local path
// dest (required) (POST /export/transaction). exportType is "csv" (default
// when empty) or "json". transactionIDs, when non-empty, exports only those
// records; otherwise the date and filter fields of opts (CreatedAtMin/Max,
// FilterCustomData/Decision/Docupass/ProfileID) select the set.
// ignoreUnrecognized and ignoreDuplicate skip those records. It returns an
// error on bad arguments, an API error, or a download failure.
func (t *TransactionService) Export(dest, exportType string, transactionIDs []string, ignoreUnrecognized, ignoreDuplicate bool, opts TransactionListOptions) error {
	if dest == "" {
		return invalid("dest is required")
	}
	if exportType == "" {
		exportType = "csv"
	}
	if exportType != "csv" && exportType != "json" {
		return invalid("exportType should be 'csv' or 'json'")
	}
	payload := map[string]any{"exportType": exportType, "ignoreUnrecognized": ignoreUnrecognized, "ignoreDuplicate": ignoreDuplicate}
	if len(transactionIDs) > 0 {
		payload["transactionId"] = transactionIDs
	}
	if opts.CreatedAtMin > 0 {
		payload["createdAtMin"] = opts.CreatedAtMin
	}
	if opts.CreatedAtMax > 0 {
		payload["createdAtMax"] = opts.CreatedAtMax
	}
	putStr(payload, "customData", opts.FilterCustomData)
	putStr(payload, "decision", opts.FilterDecision)
	putStr(payload, "docupass", opts.FilterDocupass)
	putStr(payload, "profileId", opts.FilterProfileID)

	resp, err := t.client.doJSON(http.MethodPost, "export/transaction", payload, nil)
	if err != nil {
		return err
	}
	if u, ok := resp["Url"].(string); ok && u != "" {
		return t.client.download(u, dest)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Docupass
// ---------------------------------------------------------------------------

// DocupassService provides hosted-verification ("Docupass") link management.
// Access it via Client.Docupass.
type DocupassService struct{ client *Client }

// DocupassCreateRequest holds parameters for creating a Docupass (POST /docupass).
// Profile is required; all other fields are optional.
type DocupassCreateRequest struct {
	Profile               string // KYC profile ID (required)
	Mode                  int    // 0=Document+Face, 1=Document, 2=Face, 3=e-Signature
	ContractFormat        string // generated contract format (default "pdf")
	ContractGenerate      string // contract template ID to generate and present
	ContractSign          string // contract template ID requiring an e-signature
	ContractPrefill       string // key/value data (JSON) merged into the contract
	Reusable              bool   // allow the link to be used more than once
	CustomData            string // arbitrary string echoed on the transaction
	Language              string // UI language code for the hosted page
	ReferenceDocument     string // reference document front to match against
	ReferenceDocumentBack string // reference document back to match against
	ReferenceFace         string // reference face image to match against
	UserPhone             string // end-user phone number (e.g. for SMS delivery)
	VerifyAddress         string // assert the holder's address matches this value
	VerifyAge             string // assert the age falls in this range, e.g. "18-40"
	VerifyDOB             string // assert the date of birth; docupass uses the upper-case "verifyDOB" field
	VerifyDocumentNumber  string // assert the document number matches this value
	VerifyName            string // assert the holder's name matches this value
	VerifyPostcode        string // assert the postcode matches this value
}

// Create creates a Docupass hosted-verification link from req (POST /docupass).
// req.Profile is required. It returns the decoded JSON response, or an error.
func (d *DocupassService) Create(req DocupassCreateRequest) (map[string]any, error) {
	if req.Profile == "" {
		return nil, invalid("Profile is required")
	}
	format := req.ContractFormat
	if format == "" {
		format = "pdf"
	}
	payload := map[string]any{
		"profile":          req.Profile,
		"mode":             req.Mode,
		"contractFormat":   format,
		"contractGenerate": req.ContractGenerate,
		"reusable":         req.Reusable,
	}
	putStr(payload, "contractSign", req.ContractSign)
	putStr(payload, "contractPrefill", req.ContractPrefill)
	putStr(payload, "customData", req.CustomData)
	putStr(payload, "language", req.Language)
	putStr(payload, "referenceDocument", req.ReferenceDocument)
	putStr(payload, "referenceDocumentBack", req.ReferenceDocumentBack)
	putStr(payload, "referenceFace", req.ReferenceFace)
	putStr(payload, "userPhone", req.UserPhone)
	putStr(payload, "verifyAddress", req.VerifyAddress)
	putStr(payload, "verifyAge", req.VerifyAge)
	putStr(payload, "verifyDOB", req.VerifyDOB)
	putStr(payload, "verifyDocumentNumber", req.VerifyDocumentNumber)
	putStr(payload, "verifyName", req.VerifyName)
	putStr(payload, "verifyPostcode", req.VerifyPostcode)
	return d.client.doJSON(http.MethodPost, "docupass", payload, nil)
}

// List lists Docupass records (GET /docupass). order sets the sort direction
// (1 ascending, -1 descending), limit caps the page size and offset skips
// records for pagination. It returns the decoded JSON response, or an error.
func (d *DocupassService) List(order, limit, offset int) (map[string]any, error) {
	q := url.Values{}
	q.Set("order", strconv.Itoa(order))
	q.Set("limit", strconv.Itoa(limit))
	q.Set("offset", strconv.Itoa(offset))
	return d.client.doJSON(http.MethodGet, "docupass", nil, q)
}

// Get retrieves the single Docupass identified by reference (required)
// (GET /docupass/{reference}). It returns the decoded JSON response, or an
// error.
func (d *DocupassService) Get(reference string) (map[string]any, error) {
	if reference == "" {
		return nil, invalid("reference is required")
	}
	return d.client.doJSON(http.MethodGet, "docupass/"+reference, nil, nil)
}

// Delete deletes the Docupass identified by reference (required)
// (DELETE /docupass/{reference}). It returns the decoded JSON response, or an
// error.
func (d *DocupassService) Delete(reference string) (map[string]any, error) {
	if reference == "" {
		return nil, invalid("reference is required")
	}
	return d.client.doJSON(http.MethodDelete, "docupass/"+reference, nil, nil)
}

// ---------------------------------------------------------------------------
// Profile (server-side KYC profile management)
// ---------------------------------------------------------------------------

// ProfileService provides server-side KYC profile management. Access it via
// Client.Profile.
type ProfileService struct{ client *Client }

// profileBody builds the request body for create/update, merging the profile
// name (when set) with the Profile's Override fields.
func profileBody(name string, p *Profile) map[string]any {
	body := map[string]any{}
	if name != "" {
		body["name"] = name
	}
	if p != nil {
		for k, v := range p.Override {
			body[k] = v
		}
	}
	return body
}

// List lists KYC profiles (GET /profile). order sets the sort direction (1
// ascending, -1 descending), limit caps the page size and offset skips records
// for pagination. It returns the decoded JSON response, or an error.
func (s *ProfileService) List(order, limit, offset int) (map[string]any, error) {
	q := url.Values{}
	q.Set("order", strconv.Itoa(order))
	q.Set("limit", strconv.Itoa(limit))
	q.Set("offset", strconv.Itoa(offset))
	return s.client.doJSON(http.MethodGet, "profile", nil, q)
}

// Get retrieves the KYC profile identified by profileID (required)
// (GET /profile/{id}). It returns the decoded JSON response, or an error.
func (s *ProfileService) Get(profileID string) (map[string]any, error) {
	if profileID == "" {
		return nil, invalid("profileID is required")
	}
	return s.client.doJSON(http.MethodGet, "profile/"+profileID, nil, nil)
}

// Create creates a KYC profile (POST /profile). name (required) is the profile
// label; the optional p supplies the profile's settings via its Override map.
// It returns the decoded JSON response, or an error.
func (s *ProfileService) Create(name string, p *Profile) (map[string]any, error) {
	if name == "" {
		return nil, invalid("name is required")
	}
	return s.client.doJSON(http.MethodPost, "profile", profileBody(name, p), nil)
}

// Update updates the KYC profile identified by profileID (required)
// (PUT /profile/{id}). name sets the profile label and the optional p supplies
// the settings to store via its Override map. It returns the decoded JSON
// response, or an error.
func (s *ProfileService) Update(profileID, name string, p *Profile) (map[string]any, error) {
	if profileID == "" {
		return nil, invalid("profileID is required")
	}
	return s.client.doJSON(http.MethodPut, "profile/"+profileID, profileBody(name, p), nil)
}

// Delete deletes the KYC profile identified by profileID (required)
// (DELETE /profile/{id}). It returns the decoded JSON response, or an error.
func (s *ProfileService) Delete(profileID string) (map[string]any, error) {
	if profileID == "" {
		return nil, invalid("profileID is required")
	}
	return s.client.doJSON(http.MethodDelete, "profile/"+profileID, nil, nil)
}

// Export exports the full settings of the KYC profile identified by profileID
// (required) (GET /export/profile/{id}). It returns the decoded JSON response,
// or an error.
func (s *ProfileService) Export(profileID string) (map[string]any, error) {
	if profileID == "" {
		return nil, invalid("profileID is required")
	}
	return s.client.doJSON(http.MethodGet, "export/profile/"+profileID, nil, nil)
}

// ---------------------------------------------------------------------------
// Webhook
// ---------------------------------------------------------------------------

// WebhookService provides access to webhook delivery logs. Access it via
// Client.Webhook.
type WebhookService struct{ client *Client }

// List lists webhook delivery logs (GET /webhook). order sets the sort
// direction (1 ascending, -1 descending); limit and offset paginate; event
// (when non-empty) filters by event name; success filters by delivery outcome
// (0 failed, 1 succeeded — any other value applies no filter); createdAtMin and
// createdAtMax (when non-empty) bound the creation time. It returns the decoded
// JSON response, or an error.
func (w *WebhookService) List(order, limit, offset int, event string, success int, createdAtMin, createdAtMax string) (map[string]any, error) {
	q := url.Values{}
	q.Set("order", strconv.Itoa(order))
	q.Set("limit", strconv.Itoa(limit))
	q.Set("offset", strconv.Itoa(offset))
	if event != "" {
		q.Set("event", event)
	}
	if success == 0 || success == 1 {
		q.Set("success", strconv.Itoa(success))
	}
	if createdAtMin != "" {
		q.Set("createdAtMin", createdAtMin)
	}
	if createdAtMax != "" {
		q.Set("createdAtMax", createdAtMax)
	}
	return w.client.doJSON(http.MethodGet, "webhook", nil, q)
}

// Resend re-delivers the webhook identified by webhookID (required)
// (POST /webhook/{id}). It returns the decoded JSON response, or an error.
func (w *WebhookService) Resend(webhookID string) (map[string]any, error) {
	if webhookID == "" {
		return nil, invalid("webhookID is required")
	}
	return w.client.doJSON(http.MethodPost, "webhook/"+webhookID, map[string]any{}, nil)
}

// Delete deletes the webhook delivery log identified by webhookID (required)
// (DELETE /webhook/{id}). It returns the decoded JSON response, or an error.
func (w *WebhookService) Delete(webhookID string) (map[string]any, error) {
	if webhookID == "" {
		return nil, invalid("webhookID is required")
	}
	return w.client.doJSON(http.MethodDelete, "webhook/"+webhookID, nil, nil)
}

// ---------------------------------------------------------------------------
// Account
// ---------------------------------------------------------------------------

// AccountService provides access to the authenticated account's profile and
// usage. Access it via Client.Account.
type AccountService struct{ client *Client }

// Get retrieves the current account profile, quota and usage (GET /myaccount).
// It returns the decoded JSON response, or an error.
func (a *AccountService) Get() (map[string]any, error) {
	return a.client.doJSON(http.MethodGet, "myaccount", nil, nil)
}
