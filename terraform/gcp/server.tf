# Register startup scripts. These scripts will be rendered and used when
# machines boot up.

data "template_file" "turbinia-server" {
  template = "${file("${path.module}/startup_scripts/install_server.sh")}"
  vars {}
}

resource "google_compute_instance" "turbinia-server" {
  name         = "turbinia-server"
  machine_type = "n1-standard-2"
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

  service_account {
    scopes = ["compute-ro", "storage-rw", "pubsub"]
  }

  # Provision the machine with a script.
  metadata_startup_script = "${data.template_file.turbinia-server.rendered}"
}
