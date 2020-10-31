package main

type cveSchema struct {
	CVE         string      `json:"cve"`
	URL         string      `json:"url"`
	IssueURL    string      `json:"issueUrl"`
	Description string      `json:"description"`
	Components  []string    `json:"components"`
	CVSS        *cvssSchema `json:"cvss"`
	Affected    []string    `json:"affected"`
	FixedIn     []string    `json:"fixedIn"`
}

type cvssSchema struct {
	NVD        *nvdSchema        `json:"nvd"`
	Kubernetes *kubernetesSchema `json:"kubernetes"`
}

type nvdSchema struct {
	ScoreV2  float64 `json:"scoreV2"`
	VectorV2 string  `json:"vectorV2"`
	ScoreV3  float64 `json:"scoreV3"`
	VectorV3 string  `json:"vectorV3"`
}

type kubernetesSchema struct {
	ScoreV3  float64 `json:"scoreV3"`
	VectorV3 string  `json:"vectorV3"`
}
