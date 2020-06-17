#!/bin/bash
echo "${TURBINIA_CONF}" | base64 -d > /etc/turbinia/turbinia.conf
/usr/local/bin/turbiniactl -L /var/log/turbinia/turbinia.log -S -o /var/lib/turbinia psqworker
