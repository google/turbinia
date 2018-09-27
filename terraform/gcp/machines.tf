resource "google_compute_instance" "turbinia-server" {
  name         = "turbinia-server"
  machine_type = "g1-small"
  zone         = "${var.zone}"

  # Allow to stop/start the machine to enable change machine type.
  allow_stopping_for_update = true

  # Use default Ubuntu image as operating system.
  boot_disk {
    initialize_params {
      image = "${var.ubuntu_image}"
    }
  }

  # Assign a generated public IP address. Needed for SSH access.
  network_interface {
    network       = "default"
    access_config = {}
  }

  # Provision the machine with a script.
  metadata_startup_script = "${data.template_file.turbinia-server.rendered}"
}

resource "google_compute_instance" "turbinia-worker" {
  name         = "turbinia-worker"
  machine_type = "g1-small"
  zone         = "${var.zone}"

  # How many workers to start
  count = 3

  # Allow to stop/start the machine to enable change machine type.
  allow_stopping_for_update = true

  # Use default Ubuntu image as operating system.
  boot_disk {
    initialize_params {
      image = "${var.ubuntu_image}"
    }
  }

  # Assign a generated public IP address. Needed for SSH access.
  network_interface {
    network       = "default"
    access_config = {}
  }

  # Provision the machine with a script.
  metadata_startup_script = "${data.template_file.turbinia-worker.rendered}"
}

# Enabling GCP services individually because the google_project_services
# resource type will disable services not in the list.
resource "google_project_service" "project" {
  project = "${var.project}"
  service = "cloudfunctions.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "project" {
  project = "${var.project}"
  service = "compute.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "project" {
  project = "${var.project}"
  service = "datastore.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "project" {
  project = "${var.project}"
  service = "iam.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "project" {
  project = "${var.project}"
  service = "pubsub.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "project" {
  project = "${var.project}"
  service = "storage-component.googleapis.com"
  disable_on_destroy = false
}
