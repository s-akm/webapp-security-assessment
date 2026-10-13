# 正しく作った側。ここには ★ が付かないこと
resource "aws_db_instance" "orders" {
  engine                  = "postgres"
  instance_class          = "db.t4g.micro"
  publicly_accessible     = false
  storage_encrypted       = true
  backup_retention_period = 7
  skip_final_snapshot     = false
  deletion_protection     = true
  # publicly_accessible   = true
}

resource "aws_instance" "api" {
  ami           = "ami-11111111111111111"
  instance_type = "t3.micro"
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }
}

# 起動テンプレートでメタデータの方式を決めるインスタンス
resource "aws_instance" "from_template" {
  launch_template {
    id = aws_launch_template.strict.id
  }
}

resource "aws_launch_template" "strict" {
  name_prefix = "strict-"
  metadata_options {
    http_tokens = "required"
  }
}

resource "aws_iam_policy" "reader" {
  policy = jsonencode({
    Statement = [{
      Effect = "Allow"
      Action = [
        "s3:GetObject",
      ]
      Resource = [
        "arn:aws:s3:::example-reports/*"
      ]
    }]
  })
}
