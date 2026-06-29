# GitHub runbook - IaC Checkov scan

## Objective

Push this demo folder to GitHub and run a Checkov Infrastructure as Code scan through GitHub Actions.

## Safety

Do not run `terraform apply`. The `vulnerable/` Terraform is intentionally insecure and is only for static scanning.

## Option A - Push with Git CLI

```bash
cd devsecops-iac-demo-github

git init
git branch -M main
git add .
git commit -m "Add DevSecOps IaC scanning demo"

git remote add origin https://github.com/<your-org-or-user>/devsecops-iac-demo.git
git push -u origin main
```

The push to `main` will automatically trigger the `IaC Security Scan - Checkov` workflow.

## Option B - Upload from GitHub web UI

1. Create a new empty repository in GitHub.
2. Upload the full contents of this folder, including the hidden `.github/workflows/checkov.yml` path.
3. Commit to the `main` branch.
4. Go to the Actions tab and open `IaC Security Scan - Checkov`.

## Manual run

Use this during the live demo:

1. Open the repository in GitHub.
2. Go to **Actions**.
3. Select **IaC Security Scan - Checkov**.
4. Click **Run workflow**.
5. Choose:
   - `scan_path = vulnerable`
   - `soft_fail = true` for report-only demo mode
6. Click **Run workflow**.

For gate mode, run again with `soft_fail = false`; the workflow should fail because the vulnerable Terraform intentionally violates policies.

## Demo talk track

- "This code is not being deployed. We are scanning the infrastructure definition before deployment."
- "The scan runs automatically on push or pull request, and can also be triggered manually."
- "In report-only mode, the team can view findings without blocking delivery."
- "In gate mode, the same control can block the build if agreed risk thresholds are exceeded."
- "This is how SSDLC policy becomes executable in the CI/CD pipeline."

## Expected outcome

- `vulnerable/` should produce multiple findings.
- `improved/` should produce fewer findings and demonstrates the remediation direction.
- The workflow uploads `checkov-results.json` as an artifact for review.
