resource "aws_security_group_rule" "admin" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  cidr_blocks = ["0.0.0.0/0"]
}

resource "aws_s3_bucket_acl" "assets" {
  acl = "public-read"
}

resource "aws_iam_policy" "app" {
  policy = jsonencode({
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
  })
}
