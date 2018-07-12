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

# TODO

# --- END MAIN ---


# --- AFTER MAIN (DO NOT EDIT)

date > "$${STARTUP_FINISHED_FILE}"
echo "Startup script finished successfully"

# --- END AFTER MAIN ---