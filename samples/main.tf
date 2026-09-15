# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# This code is for PoC environment only.
# This demo code is not built for production workload.

# ⚠️ DEMO VULNERABLE TERRAFORM CONFIGURATION ⚠️

provider "google" {
  project = "YOUR_PROJECT_ID"
  region  = "us-central1"
  zone    = "us-central1-a"
}

# ---------------------------------------------------------
# VULNERABILITY 1: Publicly Exposed Storage Bucket
# ---------------------------------------------------------
resource "google_storage_bucket" "user_uploads" {
  name          = "codemender-user-uploads-bucket"
  location      = "US"
  force_destroy = true
}

# BAD: Grants read access to the entire internet
resource "google_storage_bucket_iam_binding" "public_rule" {
  bucket  = google_storage_bucket.user_uploads.name
  role    = "roles/storage.objectViewer"
  members = ["allUsers"]
}

# ---------------------------------------------------------
# VULNERABILITY 2: Cloud SQL Open to the World & Hardcoded Password
# ---------------------------------------------------------
resource "google_sql_database_instance" "main_db" {
  name             = "ecommerce-db"
  database_version = "POSTGRES_14"
  region           = "us-central1"

  settings {
    tier = "db-f1-micro"

    ip_configuration {
      ipv4_enabled    = true
      require_ssl     = false # BAD: Unencrypted transit

      # BAD: Open to the entire internet
      authorized_networks {
        name  = "open-to-world"
        value = "0.0.0.0/0"
      }
    }
  }
}

# BAD: Hardcoded root password in plaintext
resource "google_sql_user" "root_user" {
  name     = "postgres"
  instance = google_sql_database_instance.main_db.name
  password = "SuperSecretPassword123!" 
}

# ---------------------------------------------------------
# VULNERABILITY 3: Over-privileged VM & Secrets in User Data
# ---------------------------------------------------------
resource "google_compute_instance" "web_server" {
  name         = "frontend-web-server"
  machine_type = "e2-micro"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  network_interface {
    network = "default"
    # BAD: Assigns an ephemeral public IP, exposing the VM directly to the internet
    access_config {}
  }

  service_account {
    # BAD: Using the default compute service account...
    email = "default"
    # ...and giving it full project-wide admin scopes. 
    # This is a massive blast radius risk if the VM is compromised.
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  }

  # BAD: Hardcoding secrets in the startup script (visible to anyone with compute viewer access)
  metadata_startup_script = <<EOF
    #!/bin/bash
    echo "Starting web server..."
    export STRIPE_API_KEY="sk_live_1234567890abcdef1234567890abcdef"
    python3 /app/vulnerable_app.py
  EOF
}
