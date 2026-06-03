package idanalyzer

// Preset KYC profile IDs.
const (
	SecurityNone   = "security_none"
	SecurityLow    = "security_low"
	SecurityMedium = "security_medium"
	SecurityHigh   = "security_high"
)

// Profile builds a KYC profile / profileOverride object that can be attached to
// scan, biometric and docupass calls, or used to create/update a stored profile
// via ProfileService.
type Profile struct {
	ID       string
	Override map[string]any
}

// NewProfile creates a Profile. If profileID is empty, SecurityNone is used.
func NewProfile(profileID string) *Profile {
	if profileID == "" {
		profileID = SecurityNone
	}
	return &Profile{ID: profileID, Override: map[string]any{}}
}

func (p *Profile) set(k string, v any) *Profile {
	if p.Override == nil {
		p.Override = map[string]any{}
	}
	p.Override[k] = v
	return p
}

func (p *Profile) CanvasSize(pixels int) *Profile          { return p.set("canvasSize", pixels) }
func (p *Profile) OrientationCorrection(b bool) *Profile   { return p.set("orientationCorrection", b) }
func (p *Profile) ObjectDetection(b bool) *Profile         { return p.set("objectDetection", b) }
func (p *Profile) AAMVABarcodeParsing(b bool) *Profile     { return p.set("AAMVABarcodeParsing", b) }
func (p *Profile) OutputSize(pixels int) *Profile          { return p.set("outputSize", pixels) }
func (p *Profile) InferFullName(b bool) *Profile           { return p.set("inferFullName", b) }
func (p *Profile) SplitFirstName(b bool) *Profile          { return p.set("splitFirstName", b) }
func (p *Profile) TransactionAuditReport(b bool) *Profile  { return p.set("transactionAuditReport", b) }
func (p *Profile) SetTimezone(tz string) *Profile          { return p.set("timezone", tz) }
func (p *Profile) Obscure(fieldKeys []string) *Profile     { return p.set("obscure", fieldKeys) }
func (p *Profile) Webhook(url string) *Profile             { return p.set("webhook", url) }

// SaveResult controls whether transaction results and output images are stored.
func (p *Profile) SaveResult(saveTransaction, saveImages bool) *Profile {
	p.set("saveResult", saveTransaction)
	if saveTransaction {
		p.set("saveImage", saveImages)
	}
	return p
}

// OutputImage controls whether an output image is returned, and its format.
func (p *Profile) OutputImage(enable bool, format string) *Profile {
	p.set("outputImage", enable)
	if enable {
		p.set("outputType", format)
	}
	return p
}

// AutoCrop enables cropping of the output image.
func (p *Profile) AutoCrop(crop, advancedCrop bool) *Profile {
	p.set("crop", crop)
	return p.set("advancedCrop", advancedCrop)
}

// Threshold sets a single validation threshold.
func (p *Profile) Threshold(key string, value float64) *Profile {
	t, ok := p.Override["thresholds"].(map[string]any)
	if !ok {
		t = map[string]any{}
		p.set("thresholds", t)
	}
	t[key] = value
	return p
}

// DecisionTrigger sets the review/reject score triggers.
func (p *Profile) DecisionTrigger(reviewTrigger, rejectTrigger float64) *Profile {
	return p.set("decisionTrigger", map[string]any{"review": reviewTrigger, "reject": rejectTrigger})
}

// SetWarning fine-tunes how a validation component affects the decision.
func (p *Profile) SetWarning(code string, enabled bool, reviewThreshold, rejectThreshold, weight float64) *Profile {
	d, ok := p.Override["decisions"].(map[string]any)
	if !ok {
		d = map[string]any{}
		p.set("decisions", d)
	}
	d[code] = map[string]any{"enabled": enabled, "review": reviewThreshold, "reject": rejectThreshold, "weight": weight}
	return p
}

func (p *Profile) acceptedDocuments() map[string]any {
	a, ok := p.Override["acceptedDocuments"].(map[string]any)
	if !ok {
		a = map[string]any{}
		p.set("acceptedDocuments", a)
	}
	return a
}

// RestrictDocumentCountry restricts accepted issuing countries (ISO Alpha-2, comma separated).
func (p *Profile) RestrictDocumentCountry(countryCodes string) *Profile {
	p.acceptedDocuments()["documentCountry"] = countryCodes
	return p
}

// RestrictDocumentState restricts accepted issuing states (comma separated).
func (p *Profile) RestrictDocumentState(states string) *Profile {
	p.acceptedDocuments()["documentState"] = states
	return p
}

// RestrictDocumentType restricts accepted document types (e.g. "PD").
func (p *Profile) RestrictDocumentType(documentType string) *Profile {
	p.acceptedDocuments()["documentType"] = documentType
	return p
}
