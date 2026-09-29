resource "aws_iam_policy" "p" {
  policy = jsonencode({ Statement = [{ actions = ["s3:*"], resources = ["*"] }] })
}
