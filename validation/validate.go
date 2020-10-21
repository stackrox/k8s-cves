package main

import (
	"regexp"
	"strings"

	"github.com/hashicorp/go-version"
	"github.com/pkg/errors"
)

var (
	cvePattern   = regexp.MustCompile(`^CVE-\d+-\d+$`)
	urlPattern   = regexp.MustCompile(`^https?://`)
	cvss2Pattern = regexp.MustCompile(`^AV:[LAN]/AC:[HML]/Au:[MSN]/C:[NPC]/I:[NPC]/A:[NPC]$`)
	cvss3Pattern = regexp.MustCompile(`^CVSS:3.[01]/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]$`)
)

func validate(fileName string, cveFile *cveSchema) error {
	// Validate CVE.
	if !cvePattern.MatchString(cveFile.CVE) {
		return errors.Errorf("CVE must adhere to the pattern %q: %s", cvePattern.String(), cveFile.CVE)
	}

	// Validate file name.
	if !strings.HasSuffix(fileName, cveFile.CVE + ".yaml") {
		return errors.Errorf("File name must match CVE (%q)", cveFile.CVE)
	}

	// Validate URL.
	if !urlPattern.MatchString(cveFile.URL) {
		return errors.Errorf("URL must adhere to the pattern %q: %s", urlPattern.String(), cveFile.URL)
	}

	// Validate description.
	if len(strings.TrimSpace(cveFile.Description)) == 0 {
		return errors.New("Description must be defined")
	}

	// Validate components.
	if len(cveFile.Components) > 0 {
		componentSet := make(map[string]bool)
		for _, component := range cveFile.Components {
			trimmed := strings.TrimSpace(component)
			if len(trimmed) == 0 {
				return errors.New("Components may not be blank")
			}
			if componentSet[trimmed] {
				return errors.Errorf("Components may not be repeated: %s", trimmed)
			}
			componentSet[trimmed] = true
		}
	}

	// Validate CVSS.
	if err := validateCVSS(cveFile.CVSS); err != nil {
		return errors.Wrap(err, "Invalid CVSS field")
	}

	// Validate affected.
	if err := validateVersionConstraints(cveFile.Affected); err != nil {
		return errors.Wrap(err, "Invalid affected field")
	}

	// Validate fixedIn.
	if err := validateVersionConstraints(cveFile.FixedIn); err != nil {
		return errors.Wrap(err, "Invalid fixedIn field")
	}

	return nil
}

func validateCVSS(cvss *cvssSchema) error {
	if cvss == nil {
		return errors.New("CVSS must be defined")
	}

	if cvss.NVD == nil && cvss.Kubernetes == nil {
		return errors.New("At least one of 'nvd' or 'kubernetes' must be defined")
	}

	if cvss.NVD != nil {
		nvd := cvss.NVD

		if nvd.ScoreV2 <= 0.0 && nvd.ScoreV3 <= 0.0 {
			return errors.New("At least one of nvd.scoreV2 or nvd.scoreV3 must be defined and greater than 0.0")
		}

		if nvd.ScoreV2 < 0.0 || nvd.ScoreV3 < 0.0 {
			return errors.New("nvd.scoreV2 and nvd.scoreV3 must be greater than 0, if defined")
		}

		if nvd.ScoreV2 > 0.0 && !cvss2Pattern.MatchString(nvd.VectorV2) {
			return errors.Errorf("nvd.vectorV2 must adhere to pattern %q: %s", cvss3Pattern.String(), nvd.VectorV3)
		}

		if nvd.ScoreV3 > 0.0 && !cvss3Pattern.MatchString(nvd.VectorV3) {
			return errors.Errorf("nvd.vectorV3 must adhere to pattern %q: %s", cvss3Pattern.String(), nvd.VectorV3)
		}
	}

	if cvss.Kubernetes != nil {
		kubernetes := cvss.Kubernetes

		if kubernetes.ScoreV3 <= 0.0 {
			return errors.New("kubernetes.scoreV3 must be defined and greater than 0.0")
		}

		if !cvss3Pattern.MatchString(kubernetes.VectorV3) {
			return errors.Errorf("kubernetes.vectorV3 must adhere to pattern %q: %s", cvss3Pattern.String(), kubernetes.VectorV3)
		}
	}

	return nil
}

func validateVersionConstraints(constraints []string) error {
	if len(constraints) == 0 {
		return errors.New("Constraints must be defined")
	}
	for _, constraint := range constraints {
		// It would be nice if we could ensure all constraints are non-overlapping,
		// but it doesn't seem very straightforward at the moment.
		if _, err := version.NewConstraint(constraint); err != nil {
			return errors.Wrapf(err, "Invalid constraint: %s", constraint)
		}
	}

	return nil
}
