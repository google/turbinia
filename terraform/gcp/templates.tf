# Register startup scripts. These scripts will be rendered and used when
# machines boot up.

data "template_file" "server" {
  template = "${file("${path.module}/startup_scripts/install_server.sh")}"
  vars {}
}

data "template_file" "client" {
  template = "${file("${path.module}/startup_scripts/install_client.sh")}"
  vars {}
}
