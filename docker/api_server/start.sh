#!/bin/bash

# Only write the Turbinia configuration file if TURBINIA_CONF is not empty and the file does not exist (or is 0 bytes in size)
if [ ! -z "$TURBINIA_CONF" ] && [ ! -s /etc/turbinia/turbinia.conf ]
then
    echo "${TURBINIA_CONF}" | base64 -d > /etc/turbinia/turbinia.conf
fi

# Start supervisord
service supervisor start

# Start Turbinia API server
supervisorctl start turbinia-api-server

# Start Oauth2 proxy if authentication is enabled
if [ `cat /etc/turbinia/turbinia.conf | grep API_AUTHENTICATION_ENABLED | cut -d'=' -f2` == 'True' ]
then 
    supervisorctl start oauth2-proxy
fi

# Don't exit
while sleep 1000; do :; done
