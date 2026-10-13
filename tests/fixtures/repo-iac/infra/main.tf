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

# 並びを複数行に分けて書いた広すぎる権限（1 行の検索では拾えない）
resource "aws_iam_policy" "worker" {
  policy = jsonencode({
    Statement = [{
      Effect = "Allow"
      Action = [
        "s3:*",
        "logs:PutLogEvents",
      ]
      Resource = [
        "*"
      ]
    }]
  })
}

# 外から届き、暗号化せず、バックアップを取らず、消したら戻せない DB
resource "aws_db_instance" "main" {
  engine                  = "postgres"
  instance_class          = "db.t4g.micro"
  publicly_accessible     = true
  backup_retention_period = 0
  skip_final_snapshot     = true
  # storage_encrypted     = true
}

# メタデータの取得方式を指定していないインスタンス（IMDSv1 が残りうる）
resource "aws_instance" "web" {
  ami           = "ami-00000000000000000"
  instance_type = "t3.micro"
}

# IMDSv1 を明示的に許しているテンプレート
resource "aws_launch_template" "batch" {
  name_prefix = "batch-"
  metadata_options {
    http_tokens = "optional"
  }
}
