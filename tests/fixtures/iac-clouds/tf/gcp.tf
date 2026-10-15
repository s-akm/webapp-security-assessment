# 架空の定義。名前と値はすべて架空

resource "google_storage_bucket" "exports" {
  name     = "example-exports"
  location = "ASIA-NORTHEAST1"
}

resource "google_storage_bucket" "locked" {
  name                     = "example-locked"
  location                 = "ASIA-NORTHEAST1"
  public_access_prevention = "enforced"
}

resource "google_storage_bucket_iam_member" "public" {
  bucket = "example-exports"
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}

resource "google_compute_firewall" "ssh" {
  name          = "ssh"
  network       = "default"
  source_ranges = ["0.0.0.0/0"]
}

# すべての IP アドレスから DB へ届く
resource "google_sql_database_instance" "main" {
  name             = "main"
  database_version = "POSTGRES_16"
  settings {
    tier = "db-f1-micro"
    ip_configuration {
      authorized_networks {
        name  = "anyone"
        value = "0.0.0.0/0"
      }
    }
  }
}

resource "google_sql_database_instance" "office" {
  name             = "office"
  database_version = "POSTGRES_16"
  settings {
    tier = "db-f1-micro"
    ip_configuration {
      authorized_networks {
        name  = "office"
        value = "198.51.100.0/24"
      }
    }
  }
}
