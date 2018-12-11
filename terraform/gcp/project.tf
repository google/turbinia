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

resource "google_project_service" "iam_" {
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
  name = "turbinia-pubsub"
}

data "local_file" "cloud-datastore-index" {
  filename = "../../turbinia/tools/gcf_init/index.yaml"
}

data "local_file" "datastore-index-file" {
  filename = "../../turbinia/tools/gcf_init/index.yaml"
}

data "local_file" "cloudfunction-zip-file" {
  filename = "../../turbinia/tools/gcf_init/index.yaml"
}
