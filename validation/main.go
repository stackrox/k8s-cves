package main

import (
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/ghodss/yaml"
	"github.com/pkg/errors"
)

const (
	cvesPath = "cves"
)

func main() {
	err := filepath.Walk(cvesPath, func(path string, _ os.FileInfo, _ error) error {
		if path == cvesPath {
			return nil
		}

		if filepath.Ext(path) != ".yaml" {
			return errors.Errorf("CVE file must have .yaml extension: %s", path)
		}

		bytes, err := ioutil.ReadFile(path)
		if err != nil {
			return err
		}

		cveFile := &cveSchema{}
		if err := yaml.Unmarshal(bytes, cveFile); err != nil {
			return errors.Wrapf(err, "Unable to unmarshal %s", path)
		}

		if err := validate(path, cveFile); err != nil {
			return errors.Wrapf(err, "CVE file %s is invalid", path)
		}

		return nil
	})

	if err != nil {
		log.Fatalf("Error validating CVEs: %v", err)
	}
}
