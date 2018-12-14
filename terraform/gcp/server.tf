# Register startup scripts. These scripts will be rendered and used when
# machines boot up.

data "template_file" "config-template" {
  template = "${file("${path.module}/files/turbinia.conf.tmpl")}"
  vars {
    project           = "${var.project}"
    region            = "${var.region}}"
    zone              = "${var.zone}"
    turbinia_id       = "${random_id.turbinia-instance-id.hex}"
    pubsub_topic      = "${google_pubsub_topic.pubsub-topic.name}"
    pubsub_topic_psq  = "${google_pubsub_topic.pubsub-topic-psq.name}"
    bucket            = "${google_storage_bucket.output-bucket.name}"
  }
}

data "template_file" "server-install-script" {
  template = "${file("${path.module}/startup_scripts/install_server.sh")}"
  vars {
    config = "${data.template_file.config-template.rendered}"
  }
}


resource "google_compute_instance" "turbinia-server" {
  name         = "turbinia-server"
  machine_type = "n1-standard-2"
  zone         = "${var.zone}"

  count        = 1

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
  metadata_startup_script = "${data.template_file.server-install-script.rendered}"
}
