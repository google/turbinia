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

# Use log file path from environment variable is it exists, else get the path from the config.
if [ ! -z ${TURBINIA_LOG_FILE+x} ]
then
    /usr/local/bin/turbiniactl -L $TURBINIA_LOG_FILE -S psqworker
else
    /usr/local/bin/turbiniactl -S psqworker
fi
