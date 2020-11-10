package validation

// CVESchema is the schema for the entire CVE file.
type CVESchema struct {
	CVE         string           `json:"cve"`
	URL         string           `json:"url"`
	IssueURL    string           `json:"issueUrl"`
	Description string           `json:"description"`
	Components  []string         `json:"components"`
	CVSS        *CVSSSchema      `json:"cvss"`
	Affected    []AffectedSchema `json:"affected"`
}

// CVSSSchema is the schema for the CVSS section of the CVE file.
type CVSSSchema struct {
	NVD        *NVDSchema        `json:"nvd"`
	Kubernetes *KubernetesSchema `json:"kubernetes"`
}

// NVDSchema is the schema for the NVD subsection of the CVE file.
type NVDSchema struct {
	ScoreV2  float64 `json:"scoreV2"`
	VectorV2 string  `json:"vectorV2"`
	ScoreV3  float64 `json:"scoreV3"`
	VectorV3 string  `json:"vectorV3"`
}

// KubernetesSchema is the schema for the Kubernetes subsection of the CVE file.
type KubernetesSchema struct {
	ScoreV3  float64 `json:"scoreV3"`
	VectorV3 string  `json:"vectorV3"`
}

// AffectedSchema is the schema for the affected section of the CVE file.
type AffectedSchema struct {
	Range   string `json:"range"`
	FixedBy string `json:"fixedBy"`
}
