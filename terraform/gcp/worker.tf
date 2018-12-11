# Register startup scripts. These scripts will be rendered and used when
# machines boot up.

data "template_file" "turbinia-worker" {
  template = "${file("${path.module}/startup_scripts/install_worker.sh")}"
  vars {}
}

resource "google_compute_instance" "turbinia-worker" {
  name         = "turbinia-worker"
  machine_type = "g1-small"
  zone         = "${var.zone}"

  # How many workers to start
  count = 0

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