# apigw_logging.tf
# GAP-08 — CloudWatch log group that receives the intake API access logs.
resource "aws_cloudwatch_log_group" "api_access" {
  name              = "/aws/apigateway/${local.name_prefix}-access"
  retention_in_days = 90
}
