#!/bin/bash

# Only write the Turbinia configuration file if TURBINIA_CONF is not empty and the file does not exist (or is 0 bytes in size)
if [ ! -z "$TURBINIA_CONF" ] && [ ! -s /etc/turbinia/turbinia.conf ]
then
    echo "${TURBINIA_CONF}" | base64 -d > /etc/turbinia/turbinia.conf
fi

# Use log file path from environment variable is it exists, else get the path from the config.
if [ ! -z ${TURBINIA_LOG_FILE+x} ]
then
    /usr/local/bin/turbiniactl -L $TURBINIA_LOG_FILE -S server
else
    /usr/local/bin/turbiniactl -S server
fi
