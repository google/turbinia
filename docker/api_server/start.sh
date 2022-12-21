#!/bin/bash

# Only write the Turbinia configuration file if TURBINIA_CONF is not empty and the file does not exist (or is 0 bytes in size)
if [ ! -z "$TURBINIA_CONF" ] && [ ! -s /etc/turbinia/turbinia.conf ]
then
    echo "${TURBINIA_CONF}" | base64 -d > /etc/turbinia/turbinia.conf
fi

# Start Turbinia API server
/usr/local/bin/turbiniactl api_server

# Don't exit
while sleep 1000; do :; done