# DevSecOps IaC demo pack

Purpose: a five-minute demo showing how an IaC security tool can shift security checks left into the developer workflow and CI/CD pipeline.

## Safety

Do not run `terraform apply`. The Terraform under `vulnerable/` is intentionally insecure and is only for static analysis.

## Local demo commands

```bash
cd devsecops-iac-demo
python3 -m venv .venv
source .venv/bin/activate
pip install checkov

# Scan intentionally vulnerable Terraform
checkov -d vulnerable --framework terraform

# Optional: create a JSON artefact
checkov -d vulnerable --framework terraform --output json > checkov-results.json

# Scan the improved sample to show remediation direction
checkov -d improved --framework terraform
```

## Suggested live demo flow - 5 minutes

1. Show `vulnerable/main.tf`: public S3 bucket policy, public access block disabled, admin ports exposed, public EC2, IMDSv1 allowed, unencrypted root disk.
2. Run `checkov -d vulnerable --framework terraform`.
3. Pick two or three failed checks and map them to risk: data exposure, admin access, weak instance hardening.
4. Open `improved/main.tf` and show the same risks remediated.
5. Run `checkov -d improved --framework terraform` and explain that the same command can run locally, in pre-commit, or in CI/CD.

## Talk track

"This is not about adding a new manual security review. It is about codifying selected controls as policy checks, running them where developers already work, and using risk-based thresholds to decide which findings block a merge or deployment."
