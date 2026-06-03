package idanalyzer

import (
	"net/http"
	"net/url"
	"strconv"
)

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------

type ScannerService struct{ client *Client }

// ScanRequest holds the inputs and options for a standard scan (POST /scan).
type ScanRequest struct {
	DocumentFront string // file path, base64, URL, or "ref:" cache reference (required)
	DocumentBack  string
	Face          string // selfie photo for biometric verification
	FaceVideo     string // selfie video for biometric verification
	Profile       *Profile

	RestrictCountry      string
	RestrictState        string
	RestrictType         string
	VerifyName           string
	VerifyDob            string // YYYY/MM/DD
	VerifyAge            string // e.g. "18-40"
	VerifyAddress        string
	VerifyPostcode       string
	VerifyDocumentNumber string
	ContractGenerate     string
	ContractFormat       string
	ContractPrefill      map[string]any
	IP                   string
	CustomData           string
}

func putStr(m map[string]any, k, v string) {
	if v != "" {
		m[k] = v
	}
}

// Scan initiates a full identity document scan and optional biometric verification.
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

// QuickScan initiates a quick OCR-only scan.
func (s *ScannerService) QuickScan(documentFront, documentBack string, cacheImage bool) (map[string]any, error) {
	return s.quick("quickscan", documentFront, documentBack, cacheImage)
}

// VeryQuickScan initiates a very fast OCR-only scan.
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

type BiometricService struct{ client *Client }

// VerifyFace performs 1:1 face verification against a reference image (POST /face).
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

type AMLService struct{ client *Client }

// AMLSearchRequest holds parameters for an AML v1 search (POST /aml).
type AMLSearchRequest struct {
	Name      string
	IDNumber  string
	Entity    int // 0=Person, 1=Corporation/Legal Entity
	Country   string
	Database  []string
	BirthYear string
}

// Search screens against the AML database (POST /aml).
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

// SearchV3 screens against the AML v3 database (POST /amlv3). Provide Text or ID.
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

type ContractService struct{ client *Client }

// Generate generates a document from a template (POST /generate).
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

// ListTemplate lists contract templates (GET /contract).
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

// GetTemplate retrieves a contract template (GET /contract/{id}).
func (c *ContractService) GetTemplate(templateID string) (map[string]any, error) {
	if templateID == "" {
		return nil, invalid("templateID is required")
	}
	return c.client.doJSON(http.MethodGet, "contract/"+templateID, nil, nil)
}

// CreateTemplate creates a contract template (POST /contract).
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

// UpdateTemplate updates a contract template (POST /contract/{id}).
func (c *ContractService) UpdateTemplate(templateID, name, content, orientation, timezone, font string) (map[string]any, error) {
	if templateID == "" {
		return nil, invalid("templateID is required")
	}
	payload := map[string]any{"name": name, "content": content, "orientation": orientation, "timezone": timezone, "font": font}
	return c.client.doJSON(http.MethodPost, "contract/"+templateID, payload, nil)
}

// DeleteTemplate deletes a contract template (DELETE /contract/{id}).
func (c *ContractService) DeleteTemplate(templateID string) (map[string]any, error) {
	if templateID == "" {
		return nil, invalid("templateID is required")
	}
	return c.client.doJSON(http.MethodDelete, "contract/"+templateID, nil, nil)
}

// ---------------------------------------------------------------------------
// Transaction
// ---------------------------------------------------------------------------

type TransactionService struct{ client *Client }

// TransactionListOptions holds filters for listing/exporting transactions.
type TransactionListOptions struct {
	Order            int
	Limit            int
	Offset           int
	CreatedAtMin     int
	CreatedAtMax     int
	FilterCustomData string
	FilterDecision   string
	FilterDocupass   string
	FilterProfileID  string
}

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

// Get retrieves a single transaction (GET /transaction/{id}).
func (t *TransactionService) Get(transactionID string) (map[string]any, error) {
	if transactionID == "" {
		return nil, invalid("transactionID is required")
	}
	return t.client.doJSON(http.MethodGet, "transaction/"+transactionID, nil, nil)
}

// List retrieves transaction history (GET /transaction).
func (t *TransactionService) List(opts TransactionListOptions) (map[string]any, error) {
	return t.client.doJSON(http.MethodGet, "transaction", nil, opts.values())
}

// Update updates a transaction decision (PATCH /transaction/{id}).
func (t *TransactionService) Update(transactionID, decision string) (map[string]any, error) {
	if transactionID == "" {
		return nil, invalid("transactionID is required")
	}
	if decision != "accept" && decision != "review" && decision != "reject" {
		return nil, invalid("decision should be one of accept, review, reject")
	}
	return t.client.doJSON(http.MethodPatch, "transaction/"+transactionID, map[string]any{"decision": decision}, nil)
}

// Delete deletes a transaction (DELETE /transaction/{id}).
func (t *TransactionService) Delete(transactionID string) (map[string]any, error) {
	if transactionID == "" {
		return nil, invalid("transactionID is required")
	}
	return t.client.doJSON(http.MethodDelete, "transaction/"+transactionID, nil, nil)
}

// SaveImage downloads a vault image to dest (GET /imagevault/{token}).
func (t *TransactionService) SaveImage(imageToken, dest string) error {
	if imageToken == "" || dest == "" {
		return invalid("imageToken and dest are required")
	}
	return t.client.download("imagevault/"+imageToken, dest)
}

// SaveFile downloads a vault file to dest (GET /filevault/{name}).
func (t *TransactionService) SaveFile(fileName, dest string) error {
	if fileName == "" || dest == "" {
		return invalid("fileName and dest are required")
	}
	return t.client.download("filevault/"+fileName, dest)
}

// Export requests a transaction archive and downloads it to dest (POST /export/transaction).
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

type DocupassService struct{ client *Client }

// DocupassCreateRequest holds parameters for creating a Docupass (POST /docupass).
type DocupassCreateRequest struct {
	Profile               string // KYC profile ID (required)
	Mode                  int    // 0=Document+Face, 1=Document, 2=Face, 3=e-Signature
	ContractFormat        string
	ContractGenerate      string
	ContractSign          string
	ContractPrefill       string
	Reusable              bool
	CustomData            string
	Language              string
	ReferenceDocument     string
	ReferenceDocumentBack string
	ReferenceFace         string
	UserPhone             string
	VerifyAddress         string
	VerifyAge             string
	VerifyDOB             string // note: docupass uses the upper-case "verifyDOB" field
	VerifyDocumentNumber  string
	VerifyName            string
	VerifyPostcode        string
}

// Create creates a Docupass link (POST /docupass).
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

// List lists Docupass records (GET /docupass).
func (d *DocupassService) List(order, limit, offset int) (map[string]any, error) {
	q := url.Values{}
	q.Set("order", strconv.Itoa(order))
	q.Set("limit", strconv.Itoa(limit))
	q.Set("offset", strconv.Itoa(offset))
	return d.client.doJSON(http.MethodGet, "docupass", nil, q)
}

// Get retrieves a single Docupass (GET /docupass/{reference}).
func (d *DocupassService) Get(reference string) (map[string]any, error) {
	if reference == "" {
		return nil, invalid("reference is required")
	}
	return d.client.doJSON(http.MethodGet, "docupass/"+reference, nil, nil)
}

// Delete deletes a Docupass (DELETE /docupass/{reference}).
func (d *DocupassService) Delete(reference string) (map[string]any, error) {
	if reference == "" {
		return nil, invalid("reference is required")
	}
	return d.client.doJSON(http.MethodDelete, "docupass/"+reference, nil, nil)
}

// ---------------------------------------------------------------------------
// Profile (server-side KYC profile management)
// ---------------------------------------------------------------------------

type ProfileService struct{ client *Client }

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

// List lists KYC profiles (GET /profile).
func (s *ProfileService) List(order, limit, offset int) (map[string]any, error) {
	q := url.Values{}
	q.Set("order", strconv.Itoa(order))
	q.Set("limit", strconv.Itoa(limit))
	q.Set("offset", strconv.Itoa(offset))
	return s.client.doJSON(http.MethodGet, "profile", nil, q)
}

// Get retrieves a KYC profile (GET /profile/{id}).
func (s *ProfileService) Get(profileID string) (map[string]any, error) {
	if profileID == "" {
		return nil, invalid("profileID is required")
	}
	return s.client.doJSON(http.MethodGet, "profile/"+profileID, nil, nil)
}

// Create creates a KYC profile (POST /profile).
func (s *ProfileService) Create(name string, p *Profile) (map[string]any, error) {
	if name == "" {
		return nil, invalid("name is required")
	}
	return s.client.doJSON(http.MethodPost, "profile", profileBody(name, p), nil)
}

// Update updates a KYC profile (PUT /profile/{id}).
func (s *ProfileService) Update(profileID, name string, p *Profile) (map[string]any, error) {
	if profileID == "" {
		return nil, invalid("profileID is required")
	}
	return s.client.doJSON(http.MethodPut, "profile/"+profileID, profileBody(name, p), nil)
}

// Delete deletes a KYC profile (DELETE /profile/{id}).
func (s *ProfileService) Delete(profileID string) (map[string]any, error) {
	if profileID == "" {
		return nil, invalid("profileID is required")
	}
	return s.client.doJSON(http.MethodDelete, "profile/"+profileID, nil, nil)
}

// Export exports a KYC profile (GET /export/profile/{id}).
func (s *ProfileService) Export(profileID string) (map[string]any, error) {
	if profileID == "" {
		return nil, invalid("profileID is required")
	}
	return s.client.doJSON(http.MethodGet, "export/profile/"+profileID, nil, nil)
}

// ---------------------------------------------------------------------------
// Webhook
// ---------------------------------------------------------------------------

type WebhookService struct{ client *Client }

// List lists webhook delivery logs (GET /webhook).
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

// Resend resends a webhook delivery (POST /webhook/{id}).
func (w *WebhookService) Resend(webhookID string) (map[string]any, error) {
	if webhookID == "" {
		return nil, invalid("webhookID is required")
	}
	return w.client.doJSON(http.MethodPost, "webhook/"+webhookID, map[string]any{}, nil)
}

// Delete deletes a webhook delivery log (DELETE /webhook/{id}).
func (w *WebhookService) Delete(webhookID string) (map[string]any, error) {
	if webhookID == "" {
		return nil, invalid("webhookID is required")
	}
	return w.client.doJSON(http.MethodDelete, "webhook/"+webhookID, nil, nil)
}

// ---------------------------------------------------------------------------
// Account
// ---------------------------------------------------------------------------

type AccountService struct{ client *Client }

// Get retrieves the current account profile, quota and usage (GET /myaccount).
func (a *AccountService) Get() (map[string]any, error) {
	return a.client.doJSON(http.MethodGet, "myaccount", nil, nil)
}
