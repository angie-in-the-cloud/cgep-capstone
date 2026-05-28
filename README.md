# Acme Health Patient Intake API — CGE-P Capstone

This repository is my CGE-P capstone submission. It forks `GRCEngClub/cgep-app-starter` (the deliberately non-compliant Patient Intake API) and wraps it in four GRC layers: a Terraform baseline, an OPA Rego policy suite, a signed-evidence GitHub Actions pipeline, and an OSCAL component definition.

**Primary framework:** CMMC Level 2 (NIST SP 800-171 Rev. 2)

For the full design write-up, see [`WRITEUP.md`](./WRITEUP.md).

---

## Verification

### Layer 1 — Terraform baseline

```bash
cd terraform
terraform init
terraform plan
```

Every gap from `GAPS.md` is closed. The plan includes:

- `aws_kms_key.cui` — customer-managed CMK with rotation enabled
- `aws_s3_bucket.evidence` with `aws_s3_bucket_object_lock_configuration.evidence` in COMPLIANCE mode
- `aws_cloudtrail.main` — multi-region trail with log-file validation
- Gap-closing overrides on the starter's S3 uploads bucket, DynamoDB table, Lambda function, IAM role, and API Gateway stage

### Layer 2 — Rego policy suite

```bash
opa test ./policies
```

Expected: `19/19 PASS` across five policies.

To run the policies against the real plan:

```bash
cd terraform && terraform show -json tfplan.binary > tfplan.json
conftest test tfplan.json --policy ../policies --all-namespaces
```

Expected: `5/5 PASS`.

### Layer 3 — GitHub Actions pipeline

Two workflows under `.github/workflows/`:

- `pr.yml` — runs Plan and Policy Check on every pull request
- `apply.yml` — runs Plan, Policy Check, Apply (manual gate), Sign, and Upload on push to `main`

Repository history shows the required two PRs:

- **PR #1 (red):** GAP-01 re-introduced, policy gate fired on `SC.L2-3.13.11`, branch protection blocked the merge
- **PR #2 (green):** compliant change, gate passed, manual approval granted, signed evidence bundle uploaded to the vault

### Layer 4 — OSCAL

```bash
trestle partial-object-validate -f oscal/components/patient-intake-component.json --element component-definition
trestle partial-object-validate -f oscal/profiles/patient-intake-profile.json --element profile
```

Expected: `VALID` on both.

### Evidence vault

Signed bundles are stored under S3 Object Lock (COMPLIANCE mode):

```bash
aws s3 ls s3://acme-health-intake-evidence-6a1ed244/bundles/ --recursive
```

Each bundle has a `.tar.gz`, a `.sig` (Cosign signature), and a `.pem` (signing certificate). Cosign verification, SHA-256 recompute, and Object Lock retention all hold against the most recent bundle.

---

## Repository layout

```
cgep-capstone/
├── README.md                          # this file
├── WRITEUP.md                         # design write-up
├── GAPS.md                            # the eight named gaps (from starter)
├── FRAMEWORKS.md                      # framework primers (from starter)
├── WORKLOAD.md                        # what the API does (from starter)
├── Makefile                           # make deploy | test | destroy
├── terraform/                         # Layer 1 — GRC baseline + gap-closing overrides
├── policies/                          # Layer 2 — five Rego policies + tests
├── .github/workflows/                 # Layer 3 — pr.yml and apply.yml
└── oscal/
    ├── components/
    │   └── patient-intake-component.json
    └── profiles/
        └── patient-intake-profile.json
```
