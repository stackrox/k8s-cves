package main

import (
	"regexp"
	"strings"

	"github.com/facebookincubator/nvdtools/cvss2"
	"github.com/facebookincubator/nvdtools/cvss3"
	"github.com/hashicorp/go-version"
	"github.com/pkg/errors"
)

var (
	cvePattern      = regexp.MustCompile(`^CVE-\d+-\d+$`)
	urlPattern      = regexp.MustCompile(`^https?://`)
	issueURLPattern = regexp.MustCompile(`^https://github.com/kubernetes/kubernetes/(?:issues|pull)/\d+$`)
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

	// Validate URLs.
	if cveFile.URL == "" && cveFile.IssueURL == "" {
		return errors.Errorf("At least one of url or issueUrl must be defined")
	}

	// Validate URL.
	if cveFile.URL != "" && !urlPattern.MatchString(cveFile.URL) {
		return errors.Errorf("URL must adhere to the pattern %q: %s", urlPattern.String(), cveFile.URL)
	}

	// Validate Issue URL.
	if cveFile.IssueURL != "" && !issueURLPattern.MatchString(cveFile.IssueURL) {
		return errors.Errorf("IssueURL must adhere to the pattern %q: %s", issueURLPattern.String(), cveFile.IssueURL)
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

		if nvd.ScoreV2 > 0.0 {
			if err := validateCVSS2(nvd.ScoreV2, nvd.VectorV2); err != nil {
				return errors.Wrap(err, "Invalid nvd CVSS2")
			}
		}

		if nvd.ScoreV3 > 0.0 {
			if err := validateCVSS3(nvd.ScoreV3, nvd.VectorV3); err != nil {
				return errors.Wrap(err, "Invalid nvd CVSS3")
			}
		}
	}

	if cvss.Kubernetes != nil {
		kubernetes := cvss.Kubernetes

		if kubernetes.ScoreV3 <= 0.0 {
			return errors.New("kubernetes.scoreV3 must be defined and greater than 0.0")
		}

		if err := validateCVSS3(kubernetes.ScoreV3, kubernetes.VectorV3); err != nil {
			return errors.Wrap(err, "Invalid kubernetes CVSS3")
		}
	}

	return nil
}

func validateVersionConstraints(constraints []string) error {
	if len(constraints) == 0 {
		return errors.New("Constraints must be defined")
	}

	constraintSet := make(map[string]bool)
	for _, constraint := range constraints {
		trimmed := strings.TrimSpace(constraint)
		if len(trimmed) == 0 {
			return errors.New("Constraints may not be blank")
		}
		if constraintSet[trimmed] {
			return errors.Errorf("Constraints may not be repeated: %s", trimmed)
		}
		constraintSet[trimmed] = true

		// It would be nice if we could ensure all constraints are non-overlapping,
		// but it doesn't seem very straightforward at the moment.
		if _, err := version.NewConstraint(trimmed); err != nil {
			return errors.Wrapf(err, "Invalid constraint: %s", constraint)
		}
	}

	return nil
}

func validateCVSS2(score float64, vector string) error {
	v, err := cvss2.VectorFromString(vector)
	if err != nil {
		return err
	}
	if err := v.Validate(); err != nil {
		return err
	}

	calculatedScore := v.Score()
	if score != calculatedScore {
		return errors.Errorf("CVSS2 score differs from calculated vector score: %f != %f", score, calculatedScore)
	}

	return nil
}

func validateCVSS3(score float64, vector string) error {
	v, err := cvss3.VectorFromString(vector)
	if err != nil {
		return err
	}
	if err := v.Validate(); err != nil {
		return err
	}

	calculatedScore := v.Score()
	if score != calculatedScore {
		return errors.Errorf("CVSS3 score differs from calculated vector score: %f != %f", score, calculatedScore)
	}

	return nil
}
