#!/bin/bash

# Only write the Turbinia configuration file if TURBINIA_CONF is not empty and the file does not exist (or is 0 bytes in size)
if [ ! -z "$OAUTH2_CONF" ] && [ ! -s /etc/turbinia/oauth2.conf ]
then
    echo "${OAUTH2_CONF}" | base64 -d > /etc/turbinia/oauth2.conf
fi

# Write the auth.txt file
if [ ! -z "$OAUTH2_AUTH_EMAILS" ] && [ ! -s /etc/turbinia/auth.txt ]
then
    echo "${OAUTH2_AUTH_EMAILS}" | base64 -d > /etc/turbinia/auth.txt
fi

oauth2-proxy --config /etc/turbinia/oauth2.conf 

# Don't exit
while sleep 1000; do :; done
