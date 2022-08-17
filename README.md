# k8s-cves

This repository is meant to be a single source of truth for
Kubernetes-related CVEs. The data gathered here is meant to be as up-to-date
as possible. Currently, the data comes from a combination of:

* NVD
* Kubernetes GitHub issues
* Announcements from [kubernetes-security-announce](https://groups.google.com/g/kubernetes-security-announce)

Though this repository is meant to be a single source of truth,
there may be mistakes. We try to keep everything as accurate and up-to-date
as possible, but it is possible for things to fall through the cracks,
or data to be input incorrectly. If you find any incorrect data, please feel free
to make a pull request, and we will review it.

## YAML Format

```yaml
cve: 'CVEID (ex: CVE-2019-16276)'
url: Alternate URL for the vulnerability. This will typically be a link to NVD.
issueUrl: URL to the relevant Issue/Pull Request in the Kubernetes GitHub repository
published: 'Date CVE was first published publicly (ex: 2006-01-02)'
description: CVE description
components:
  # list of affected components
  # ex:
  - kubelet
  - kube-proxy
cvss:
  nvd:
    scoreV2: NVD V2 score
    vectorV2: NVD V2 vector
    scoreV3: NVD V3 score
    vectorV3: NVD V3 vector
  kubernetes:
    scoreV3: Kubernetes V3 score
    vectorV3: Kubernetes V3 vector
affected:
  # list of version constraints affected by the vulnerability
  # with corresponding fix version, if it exists.
  # ranges should be in order from oldest to newest.
  #
  # Constraints adhere to https://github.com/hashicorp/go-version.
  # ex:
  - range: "< 1.14.8"
    fixedBy: "1.14.8"
  - range: ">= 1.15.0, <= 1.15.4"
    fixedBy: "1.15.5"
  - range: ">= 1.16, < 1.16.0"
    fixedBy: "1.16.1"
```
