#!/bin/bash

# Only write the Turbinia configuration file if TURBINIA_CONF is not empty and the file does not exist (or is 0 bytes in size)
if [ ! -z "$OAUTH2_CONF" ] && [ ! -s /etc/turbinia/oauth2.conf ]
then
    echo "${OAUTH2_CONF}" | base64 -d > /etc/turbinia/oauth2.conf
fi

oauth2-proxy --config /etc/turbinia/oauth2.conf 

# Don't exit
while sleep 1000; do :; done
