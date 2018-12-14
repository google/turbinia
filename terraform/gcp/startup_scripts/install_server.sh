#!/bin/bash


# --- BEFORE MAIN (DO NOT EDIT) ---

# Exit on any error
set -e

# Default constants.
readonly BOOT_FINISHED_FILE="/var/lib/cloud/instance/boot-finished"
readonly STARTUP_FINISHED_FILE="/var/lib/cloud/instance/startup-script-finished"

# Redirect stdout and stderr to logfile
exec > /var/log/terraform_provision.log
exec 2>&1

# Exit if the startup script has already been executed successfully
if [[ -f "$${STARTUP_FINISHED_FILE}" ]]; then
  exit 0
fi

# Wait for cloud-init to finish all tasks
until [[ -f "$${BOOT_FINISHED_FILE}" ]]; do
  sleep 1
done

# --- END BEFORE MAIN ---


# --- MAIN ---

apt update
apt -y install python-pip

# Install Turbinia
pip install https://github.com/google/turbinia/archive/master.zip

# Turbinia needs a recent version of urllib3
pip install urllib3 --upgrade

# Create system user
useradd -r -s /bin/nologin turbinia

# Enable systemd Turbinia service
curl -o /etc/systemd/system/turbinia@.service https://raw.githubusercontent.com/google/turbinia/master/tools/turbinia%40.service
systemctl daemon-reload
systemctl enable turbinia@server
systemctl restart turbinia@server

# Configure
mkdir /etc/turbinia
echo "${config}" > /etc/turbinia/turbinia.conf

# --- END MAIN ---


# --- AFTER MAIN (DO NOT EDIT)

date > "$${STARTUP_FINISHED_FILE}"
echo "Startup script finished successfully"

# --- END AFTER MAIN ---