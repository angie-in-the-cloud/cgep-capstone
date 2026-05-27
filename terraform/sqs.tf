# sqs.tf
# GAP-06 — dead-letter queue for the intake Lambda.
# Failed intake invocations land here instead of being silently dropped,
# so a failed CUI submission is recoverable.

resource "aws_sqs_queue" "intake_dlq" {
  name = "${local.name_prefix}-intake-dlq"

  # Encrypt the queue with the same customer CMK as the other data stores.
  # A failed invocation's payload can contain CUI, so the DLQ needs CMK custody too.
  kms_master_key_id = aws_kms_key.cui.id

  # Retain failed messages 14 days - the max - so there is time to inspect
  # and replay a dropped submission.
  message_retention_seconds = 1209600

  tags = { Name = "${local.name_prefix}-intake-dlq" }
}
