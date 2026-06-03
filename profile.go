package idanalyzer

// Preset KYC profile IDs. These built-in profiles select progressively
// stricter verification rules and can be passed to NewProfile.
const (
	SecurityNone   = "security_none"   // no enforced validation rules
	SecurityLow    = "security_low"    // minimal validation
	SecurityMedium = "security_medium" // balanced validation
	SecurityHigh   = "security_high"   // strictest validation
)

// Profile builds a KYC profile / profileOverride object that can be attached to
// scan, biometric and docupass calls, or used to create/update a stored profile
// via ProfileService. Its setter methods mutate the receiver and return it, so
// they can be chained.
type Profile struct {
	ID       string         // preset or stored profile ID (see the Security* constants)
	Override map[string]any // per-call setting overrides applied on top of the profile
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

// CanvasSize sets the maximum dimension, in pixels, to which input images are
// scaled before processing. It returns the receiver for chaining.
func (p *Profile) CanvasSize(pixels int) *Profile { return p.set("canvasSize", pixels) }

// OrientationCorrection enables automatic rotation of misaligned document
// images. It returns the receiver for chaining.
func (p *Profile) OrientationCorrection(b bool) *Profile { return p.set("orientationCorrection", b) }

// ObjectDetection enables detection of physical/screen/printout document
// presentation. It returns the receiver for chaining.
func (p *Profile) ObjectDetection(b bool) *Profile { return p.set("objectDetection", b) }

// AAMVABarcodeParsing enables parsing of the AAMVA PDF417 barcode on North
// American IDs. It returns the receiver for chaining.
func (p *Profile) AAMVABarcodeParsing(b bool) *Profile { return p.set("AAMVABarcodeParsing", b) }

// OutputSize sets the maximum dimension, in pixels, of returned output images.
// It returns the receiver for chaining.
func (p *Profile) OutputSize(pixels int) *Profile { return p.set("outputSize", pixels) }

// InferFullName enables deriving the full name when only name parts are
// present. It returns the receiver for chaining.
func (p *Profile) InferFullName(b bool) *Profile { return p.set("inferFullName", b) }

// SplitFirstName enables splitting a combined first/middle name into separate
// fields. It returns the receiver for chaining.
func (p *Profile) SplitFirstName(b bool) *Profile { return p.set("splitFirstName", b) }

// TransactionAuditReport enables generation of a PDF audit report for the
// transaction. It returns the receiver for chaining.
func (p *Profile) TransactionAuditReport(b bool) *Profile {
	return p.set("transactionAuditReport", b)
}

// SetTimezone sets the timezone (e.g. "America/New_York") used for timestamps
// in results and reports. It returns the receiver for chaining.
func (p *Profile) SetTimezone(tz string) *Profile { return p.set("timezone", tz) }

// Obscure lists result field keys whose values should be redacted from the
// response. It returns the receiver for chaining.
func (p *Profile) Obscure(fieldKeys []string) *Profile { return p.set("obscure", fieldKeys) }

// Webhook sets the URL to which transaction results are POSTed. It returns the
// receiver for chaining.
func (p *Profile) Webhook(url string) *Profile { return p.set("webhook", url) }

// SaveResult controls whether transaction results and output images are
// stored. saveTransaction enables persisting the transaction record;
// saveImages (honored only when saveTransaction is true) also stores the
// images. It returns the receiver for chaining.
func (p *Profile) SaveResult(saveTransaction, saveImages bool) *Profile {
	p.set("saveResult", saveTransaction)
	if saveTransaction {
		p.set("saveImage", saveImages)
	}
	return p
}

// OutputImage controls whether an output image is returned and, when enable is
// true, its format (e.g. "jpg" or "png"). It returns the receiver for
// chaining.
func (p *Profile) OutputImage(enable bool, format string) *Profile {
	p.set("outputImage", enable)
	if enable {
		p.set("outputType", format)
	}
	return p
}

// AutoCrop enables cropping of the output image. crop enables basic edge
// cropping; advancedCrop enables perspective-corrected cropping. It returns the
// receiver for chaining.
func (p *Profile) AutoCrop(crop, advancedCrop bool) *Profile {
	p.set("crop", crop)
	return p.set("advancedCrop", advancedCrop)
}

// Threshold sets a single named validation threshold (key) to value within the
// profile's thresholds map. It returns the receiver for chaining.
func (p *Profile) Threshold(key string, value float64) *Profile {
	t, ok := p.Override["thresholds"].(map[string]any)
	if !ok {
		t = map[string]any{}
		p.set("thresholds", t)
	}
	t[key] = value
	return p
}

// DecisionTrigger sets the aggregate score triggers that move a transaction to
// "review" (reviewTrigger) or "reject" (rejectTrigger). It returns the receiver
// for chaining.
func (p *Profile) DecisionTrigger(reviewTrigger, rejectTrigger float64) *Profile {
	return p.set("decisionTrigger", map[string]any{"review": reviewTrigger, "reject": rejectTrigger})
}

// SetWarning fine-tunes how the validation component identified by code affects
// the decision: enabled toggles the component, reviewThreshold and
// rejectThreshold set its per-component score triggers, and weight scales its
// contribution. It returns the receiver for chaining.
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

// RestrictDocumentCountry restricts accepted issuing countries to countryCodes
// (ISO Alpha-2, comma separated). It returns the receiver for chaining.
func (p *Profile) RestrictDocumentCountry(countryCodes string) *Profile {
	p.acceptedDocuments()["documentCountry"] = countryCodes
	return p
}

// RestrictDocumentState restricts accepted issuing states to states (comma
// separated). It returns the receiver for chaining.
func (p *Profile) RestrictDocumentState(states string) *Profile {
	p.acceptedDocuments()["documentState"] = states
	return p
}

// RestrictDocumentType restricts accepted document types to documentType (a
// combination of the type codes, e.g. "PD" for passport and driver license). It
// returns the receiver for chaining.
func (p *Profile) RestrictDocumentType(documentType string) *Profile {
	p.acceptedDocuments()["documentType"] = documentType
	return p
}
