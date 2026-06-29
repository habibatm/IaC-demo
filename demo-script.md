# Five-minute demo script

00:00-00:30 - Set context
"We have talked about SSDLC controls and toolchain options. I will now show a small IaC example. Nothing is deployed; this is a static scan before infrastructure reaches the cloud."

00:30-01:15 - Show vulnerable Terraform
Point to: public S3 policy, public access block disabled, 0.0.0.0/0 on SSH/RDP, public EC2, IMDSv1 allowed, unencrypted root volume.

01:15-02:30 - Run scan
Command: `checkov -d vulnerable --framework terraform`

02:30-03:30 - Interpret findings
Translate findings into architectural risks: data exposure, exposed admin surface, weak hardening, missing guardrails.

03:30-04:30 - Show remediation
Open `improved/main.tf`: public access blocked, S3 encryption/versioning, restricted admin CIDR, no public IP, IMDSv2 required, encrypted root disk.

04:30-05:00 - Close
"In a real pipeline, we would start in advisory mode, agree severity thresholds and exception handling, then make high-risk policies blocking gates for the right application risk profile."
