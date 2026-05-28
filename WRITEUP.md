# WRITEUP — Acme Health Patient Intake API GRC Capstone

**Primary framework:** CMMC Level 2 (NIST SP 800-171 Rev. 2)

---

## 1. Framework Choice

I selected CMMC Level 2 as the primary framework because it aligned most directly with both the business scenario and the technical goals of the capstone. The scenario describes a federal pilot opportunity, making CMMC a stronger strategic priority than HIPAA or SOC 2 because CMMC attestation is a contractual requirement for Department of Defense (DoD) work involving Controlled Unclassified Information (CUI). HIPAA remains a legal baseline for handling healthcare data, and SOC 2 remains relevant for commercial customers, but neither provides the same contractual gate for federal opportunities.

CMMC Level 2 also mapped more effectively to the implementation-focused nature of the project. The framework's practices are specific, testable, and well-suited for enforcement through Terraform, OPA policies, CI/CD validation, and OSCAL traceability. Controls such as least privilege IAM access, encryption with customer-managed KMS keys, VPC isolation, audit logging, and continuous policy enforcement could be directly tied to CMMC practices and validated automatically during deployment workflows. While the implemented controls also improve alignment with HIPAA Security Rule and SOC 2 Trust Services Criteria, this project focuses specifically on the technical implementation and evidence-generation requirements associated with CMMC Level 2.

---

## 2. Gap Remediation

Every gap from `GAPS.md` is closed. Five are also enforced by Rego policies that fail the policy gate if the gap is re-introduced. The other three are closed in Terraform and tracked in OSCAL.

| Gap | Root cause | Layer | CMMC control |
|---|---|---|---|
| GAP-01 | S3 uploads bucket using SSE-S3 instead of SSE-KMS with a CMK | Terraform + Rego | SC.L2-3.13.11 |
| GAP-02 | DynamoDB using AWS-owned key instead of a customer-managed CMK | Terraform + Rego | SC.L2-3.13.11 |
| GAP-03 | S3 bucket lacks TLS-only policy | Terraform + Rego | SC.L2-3.13.8 |
| GAP-04 | S3 versioning disabled, PHI overwrites unrecoverable | Terraform | MP.L2-3.8.9 |
| GAP-05 | Lambda outside the VPC the starter provisions | Terraform + Rego | SC.L2-3.13.1 |
| GAP-06 | No DLQ, no X-Ray, no concurrency guard | Terraform | SI.L2-3.14.6 |
| GAP-07 | IAM role uses `dynamodb:*` and `s3:*` wildcards | Terraform + Rego | AC.L2-3.1.5 |
| GAP-08 | API Gateway: no access logging | Terraform | AU.L2-3.3.1 |

### GAP-01 and GAP-02: Customer-Managed Encryption

The starter application relied on AWS-owned keys for both the uploads bucket and the DynamoDB intake table. To remediate these gaps, I provisioned a customer-managed KMS key (`aws_kms_key.cui`) with automatic rotation enabled and configured both resources to use SSE-KMS encryption.

A single shared CMK was intentionally used because the environment contains a single workload and data classification boundary. Separate per-resource keys would have increased operational overhead without materially improving isolation for this deployment.

The policy suite enforces these controls through:

- `policies/s3_kms_encryption.rego`
- `policies/dynamodb_kms_encryption.rego`

Both policies fail the pipeline if customer-managed encryption is removed or downgraded.

### GAP-03: TLS Enforcement

The uploads bucket initially lacked a policy enforcing TLS-only transport. I added `aws_s3_bucket_policy.uploads_tls` with a deny statement conditioned on `aws:SecureTransport = false` to block non-TLS requests at the bucket layer.

`policies/s3_tls_enforcement.rego` fails the policy gate if the TLS enforcement policy is missing.

### GAP-04: S3 Versioning

The uploads bucket shipped without versioning enabled, creating the risk of unrecoverable overwrites or accidental deletions. I remediated this by enabling `aws_s3_bucket_versioning.uploads`.

This gap was addressed in Terraform only. The Rego policies prioritized the highest-risk controls most likely to regress during infrastructure changes: encryption, TLS enforcement, network boundaries, and least-privilege IAM.

### GAP-05: Lambda VPC Isolation

The starter Lambda function was deployed outside the VPC and had unrestricted outbound internet access. I remediated this by attaching the Lambda function to the starter repository's private subnets using a dedicated security group.

Rather than building parallel networking infrastructure, the implementation reused the VPC already provisioned by the starter application. To support private AWS service access without internet egress, I provisioned:

- gateway endpoints for S3 and DynamoDB
- interface endpoints for KMS and CloudWatch Logs

This was the most operationally complex gap to close because moving the Lambda into the VPC required additional IAM permissions, endpoint routing, security groups, and supporting network resources.

`policies/lambda_vpc.rego` fails the policy gate if the Lambda configuration does not include VPC subnet assignments.

### GAP-06: Operational Monitoring Controls

The starter application lacked dead-letter queue support, X-Ray tracing, and concurrency protections. I added:

- `aws_sqs_queue.intake_dlq`
- Lambda dead-letter queue configuration
- active X-Ray tracing

Reserved concurrency was intentionally not configured because the sandbox account concurrency quota would not support a reservation without exhausting the unreserved execution pool. In production, reserved concurrency would be tuned using real workload metrics.

### GAP-07: Least-Privilege IAM

The starter IAM policy granted `dynamodb:*` and `s3:*` permissions against workload resources. I replaced these wildcard permissions with narrowly scoped actions required by the application:

- `dynamodb:GetItem`
- `dynamodb:PutItem`
- `s3:GetObject`
- `s3:PutObject`

`policies/iam_no_wildcard.rego` fails the pipeline if wildcard actions are introduced into workload IAM policies.

The GitHub Actions pipeline role is excluded from this check because its permissions are infrastructure-administrative rather than workload-operational and are reviewed separately as part of pipeline governance.

### GAP-08: API Gateway Access Logging

The starter API Gateway stage did not include access logging. I added a dedicated CloudWatch log group and configured `access_log_settings` on the API Gateway stage.

These logs provide application-layer audit records including request metadata, response status, and request timing. This complements the CloudTrail trail provisioned separately for control-plane logging, allowing the environment to maintain both operational and infrastructure audit visibility.

---

## 3. Design Decisions

### Object Lock: COMPLIANCE mode

I chose COMPLIANCE mode for the evidence vault. COMPLIANCE makes objects truly immutable for the retention period — not even the root account can delete or overwrite them.

I considered GOVERNANCE mode and rejected it. GOVERNANCE is more operationally manageable and is the right choice for most production audit-trail buckets because it preserves an escape hatch for legitimate cases like legal holds released early or accidental retention misconfiguration. COMPLIANCE mode provided the strongest immutability guarantees for demonstrating chain-of-custody in this capstone. If a privileged user can override the retention, the chain-of-custody claim is weaker than it appears on the artifact.

Retention is set to 1 day, which is proportionate to capstone scope rather than a production retention schedule. A real Acme Health deployment would set retention based on the longest applicable obligation under HIPAA, SOC 2, and DoD CUI rules — likely seven years.

### Manual approval gate on apply

The pipeline applies on merge to `main`, but Apply, Sign, and Upload are gated behind a GitHub Environment with required reviewers. The pull request workflow runs Plan and Policy Check only, with no AWS write permissions. After merge, the apply workflow runs Plan and Policy Check again (defense in depth), then pauses at the production environment until a human approves it.

Auto-apply was a defensible alternative. It would have produced a faster, more automated demonstration. I chose the manual gate because organizations handling CUI under CMMC L2 almost always have a human approval step on production changes — separation of duties (AC.L2-3.1.4) is the explicit control, and it is one of the things an assessor looks for as a procedural artifact. The policy gate is a strong technical control but it is not a replacement for the human approval an assessor expects to see.

### Single AWS account

The evidence vault and the workload run in the same AWS account. A cleaner architecture separates the vault into a dedicated account so a compromised workload-account principal cannot reach the audit trail at all. I kept everything in one account because the capstone is a 30-day sprint in a sandbox, and standing up cross-account infrastructure (account vending, cross-account IAM, separated Terraform state) would introduce more operational risk than it mitigates inside the capstone window. Object Lock COMPLIANCE on the vault bucket and CloudTrail on the workload account provide compensating controls.

### Fresh OIDC role rather than reusing one

I provisioned a fresh GitHub Actions OIDC role (`acme-health-intake-github-actions`) in the capstone Terraform, scoped to the resources the pipeline actually touches. Reusing an existing lab role would have been faster but would have given the capstone pipeline more access than it needs and broken the principle of least privilege the rest of the project is built around. The trust policy restricts the role to this repo and to the `production` Environment, so a workflow on a different branch or in a fork cannot assume the role.

---

## 4. Policy Suite

Five Rego policies live under `policies/`. Each has a metadata block naming the framework, control ID, severity, and remediation; a passing fixture and a failing fixture; and a deny message that cites the CMMC L2 control ID. Conftest runs the suite against the Terraform plan in the policy-check stage of both workflows.

| Policy | Gap | Control |
|---|---|---|
| `s3_kms_encryption.rego` | GAP-01 | SC.L2-3.13.11 |
| `dynamodb_kms_encryption.rego` | GAP-02 | SC.L2-3.13.11 |
| `s3_tls_enforcement.rego` | GAP-03 | SC.L2-3.13.8 |
| `lambda_vpc.rego` | GAP-05 | SC.L2-3.13.1 |
| `iam_no_wildcard.rego` | GAP-07 | AC.L2-3.1.5 |

All five policies pass 19 of 19 fixture tests under `opa test`, and all five pass against the real Terraform plan under Conftest.

The policy suite is preventive, not remedial. Terraform closed the gaps in the current deployment. The Rego policies block them from coming back. A developer who reverts SSE-KMS to AES256 during a refactor, or who pastes a wildcard IAM statement from another project, will see the gate fail with the specific control ID in the error message before the change can merge.

I prioritized Rego enforcement for the control families most likely to regress during infrastructure changes: encryption, TLS enforcement, network boundaries, and least-privilege IAM. The remaining gaps (GAP-04 versioning, GAP-06 observability, and GAP-08 access logging) are implemented directly in Terraform and tracked in OSCAL.

---

## 5. OSCAL Component Note

The OSCAL component in this repository documents only the controls and resources that were actually implemented as part of the capstone. All implementation statements reference real Terraform resources, including the KMS key, evidence vault, CloudTrail trail, API Gateway logging configuration, Lambda VPC integration, and Rego-enforced policy controls.

Because NIST does not publish an OSCAL catalog for SP 800-171 Rev. 2, the component uses the official NIST SP 800-171 Rev. 3 OSCAL catalog published in the `usnistgov/oscal-content` repository. The implementation statements map directly to the equivalent CMMC Level 2 practice identifiers used throughout the Terraform and Rego policy layers.

The OSCAL component intentionally excludes organizational and procedural controls that were not implemented in code, such as workforce training, incident response processes, or periodic access reviews. This scoping decision followed the capstone guidance that the OSCAL artifacts should accurately describe the deployed system rather than claim controls that were not technically implemented or evidenced within the repository.

Both the component definition and profile validate successfully with Trestle, and all evidence references point to real signed artifacts stored in the immutable evidence vault.

---

## 6. What I'd Do With Another Sprint

### Cross-account evidence vault

The brief notes that a separate evidence-vault account is cleaner than a single-account deployment. This build uses a single account because that is acceptable within the scope of a 30-day capstone. A production Acme Health deployment would place the vault in a dedicated account so that compromise of the workload account could not also compromise the audit trail.

### Process controls as a second OSCAL component

A second `oscal/components/acme-health-processes.json` component would document the organizational controls that surround the technical implementation, including annual access reviews, audit-log review cadence, incident response procedures, and workforce training. Together, the technical and process components would provide a more complete representation of a full CMMC Level 2 implementation.

### Additional Rego coverage

GAP-04, GAP-06, and GAP-08 are currently enforced in Terraform only. With another sprint, generalized Rego policies for versioning, observability controls, and API access logging would extend preventative enforcement across any future S3 buckets, Lambda functions, or API Gateway stages added to the environment.

### Production-grade retention

The evidence vault currently uses a 1-day Object Lock retention period as a capstone-appropriate proxy. A production deployment would align retention with the longest applicable regulatory and contractual obligation under HIPAA, SOC 2, and DoD CUI handling requirements — likely seven years.

### Automated OSCAL validation in CI

`trestle partial-object-validate` currently runs locally before commit. In a production deployment, OSCAL validation would run automatically in CI on every pull request affecting `oscal/` artifacts so that invalid component definitions or profiles could not merge into main.

---

## 7. Limitations

The evidence vault is in the same AWS account as the workload, retention is set to 1 day rather than a production schedule, and reserved concurrency was not configured on the Lambda because the sandbox concurrency ceiling does not allow it. Each of these is documented in the relevant section above. A real Acme Health deployment would separate the vault into a dedicated account, set retention to seven years, and set reserved concurrency once production load data is available.

The build also does not include a continuous monitoring or detection layer. CloudTrail captures control-plane events and API Gateway access logging captures application requests, but no detection logic reacts to those events in real time. A production deployment would add CloudWatch metric filters and alarms targeting high-risk events (root account usage, IAM policy changes, KMS key deletion, CloudTrail configuration changes), routed to an SNS topic for alert delivery, converting the audit trail from a forensic record into a real-time detection layer.
