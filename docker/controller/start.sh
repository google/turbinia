#!/bin/bash

# Only write the Turbinia configuration file if TURBINIA_CONF is not empty and the file does not exist (or is 0 bytes in size)
if [ ! -z "$TURBINIA_CONF" ] && [ ! -s /etc/turbinia/turbinia.conf ]
then
    echo "${TURBINIA_CONF}" | base64 -d > /etc/turbinia/turbinia.conf
fi

if [ ! -z ${TURBINIA_OUTPUT_DIR} ] && [ ! -d ${TURBINIA_OUTPUT_DIR} ]
then
  sudo mkdir -p ${TURBINIA_OUTPUT_DIR}
  sudo chown turbinia:turbinia ${TURBINIA_OUTPUT_DIR}
fi

if [ ! -z ${TURBINIA_TMP_DIR} ] && [ ! -d ${TURBINIA_TMP_DIR} ]
then
  sudo mkdir -p ${TURBINIA_TMP_DIR}
  sudo chown turbinia:turbinia ${TURBINIA_TMP_DIR}
fi

# Allows pod to run without being terminated in a Kubernetes cluster
tail -f /dev/null