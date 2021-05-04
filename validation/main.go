package main

import (
	"log"
	"os"
	"path/filepath"

	"github.com/ghodss/yaml"
	"github.com/pkg/errors"
	"github.com/stackrox/k8s-cves/pkg/validation"
)

const (
	cvesPath = "cves"
)

func main() {
	err := filepath.Walk(cvesPath, func(path string, _ os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if path == cvesPath {
			return nil
		}

		if filepath.Ext(path) != ".yaml" {
			return errors.Errorf("CVE file must have .yaml extension: %s", path)
		}

		bytes, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		var cveFile validation.CVESchema
		if err := yaml.Unmarshal(bytes, &cveFile); err != nil {
			return errors.Wrapf(err, "unable to unmarshal %s", path)
		}

		if err := validation.Validate(path, &cveFile); err != nil {
			return errors.Wrapf(err, "CVE file %s is invalid", path)
		}

		return nil
	})

	if err != nil {
		log.Fatalf("Error validating CVEs: %v", err)
	}
}
