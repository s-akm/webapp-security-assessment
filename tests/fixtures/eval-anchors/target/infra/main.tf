resource "aws_s3_bucket" "logs" {
  bucket = "app-logs"
  acl    = "public-read" # vulnerable: anyone can read the logs
  tags   = { Name = "training-build-7" }
}
// injection of the bucket name
