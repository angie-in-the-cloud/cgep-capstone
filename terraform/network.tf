# network.tf
# Networking baseline for GAP-05 — moves the intake Lambda into the
# starter's VPC. Security group + VPC endpoints so the Lambda keeps a
# path to AWS services without a NAT gateway or public internet.

# Security group for the intake Lambda.
# No inbound rules — Lambda is invoked by the API Gateway service, not
# over the network.
resource "aws_security_group" "lambda" {
  name        = "${local.name_prefix}-lambda-sg"
  description = "Intake Lambda - egress to VPC endpoints only"
  vpc_id      = aws_vpc.main.id

  # Egress to interface endpoints (KMS, Logs) - their ENIs sit in the VPC CIDR.
  egress {
    description = "HTTPS to interface VPC endpoints"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.42.0.0/16"]
  }

  # Egress to gateway endpoints (S3, DynamoDB) - their traffic targets
  # AWS service IP ranges addressed via managed prefix lists, not the CIDR.
  egress {
    description = "HTTPS to S3 and DynamoDB gateway endpoints"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    prefix_list_ids = [
      data.aws_prefix_list.s3.id,
      data.aws_prefix_list.dynamodb.id,
    ]
  }

  tags = { Name = "${local.name_prefix}-lambda-sg" }
}

# Dedicated route table for the private subnets.
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  tags = { Name = "${local.name_prefix}-private-rt" }
}

resource "aws_route_table_association" "private" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# VPC endpoints — keep the Lambda's traffic to AWS services inside the VPC.

# S3 — gateway endpoint.
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]

  tags = { Name = "${local.name_prefix}-s3-endpoint" }
}

# DynamoDB — gateway endpoint.
resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]

  tags = { Name = "${local.name_prefix}-dynamodb-endpoint" }
}

# Prefix lists for the gateway endpoints, read from the endpoints themselves.
data "aws_prefix_list" "s3" {
  prefix_list_id = aws_vpc_endpoint.s3.prefix_list_id
}

data "aws_prefix_list" "dynamodb" {
  prefix_list_id = aws_vpc_endpoint.dynamodb.prefix_list_id
}

# KMS — interface endpoint.
resource "aws_vpc_endpoint" "kms" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.kms"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true

  tags = { Name = "${local.name_prefix}-kms-endpoint" }
}

# CloudWatch Logs — interface endpoint.
resource "aws_vpc_endpoint" "logs" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.logs"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true

  tags = { Name = "${local.name_prefix}-logs-endpoint" }
}

# Security group for the interface VPC endpoints (KMS, Logs).
resource "aws_security_group" "endpoints" {
  name        = "${local.name_prefix}-endpoints-sg"
  description = "Interface VPC endpoints - inbound HTTPS from Lambda"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "HTTPS from the intake Lambda"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.lambda.id]
  }

  tags = { Name = "${local.name_prefix}-endpoints-sg" }
}
