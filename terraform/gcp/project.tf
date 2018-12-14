# Enabling GCP services individually because the google_project_services
# resource type will disable services not in the list.

resource "google_project_service" "cloudfunctions" {
  project = "${var.project}"
  service = "cloudfunctions.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "compute" {
  project = "${var.project}"
  service = "compute.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "datastore" {
  project = "${var.project}"
  service = "datastore.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "iam" {
  project = "${var.project}"
  service = "iam.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "pubsub" {
  project = "${var.project}"
  service = "pubsub.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "storage-component" {
  project = "${var.project}"
  service = "storage-component.googleapis.com"
  disable_on_destroy = false
}

resource "google_pubsub_topic" "pubsub-topic" {
  name = "turbinia-${random_id.turbinia-instance-id.hex}"
}

resource "google_pubsub_topic" "pubsub-topic-psq" {
  name = "turbinia-${random_id.turbinia-instance-id.hex}-psq"
}

resource "random_id" "turbinia-instance-id" {
  byte_length = 8
}

resource "google_storage_bucket" "output-bucket" {
  name = "turbinia-${random_id.turbinia-instance-id.hex}"
}

data "local_file" "datastore-index-file" {
  filename = "../../tools/gcf_init/index.yaml"
}

resource "null_resource" "cloud-datastore-create-index" {
  provisioner "local-exec" {
    command = "gcloud datastore indexes create ${data.local_file.datastore-index-file.filename} --project=${var.project}"
  }
}

