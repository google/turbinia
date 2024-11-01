#!/bin/bash
mkdir redis-data
mkdir evidence
mkdir conf
chmod 777 conf evidence redis-data
sed -f docker/local/local-config.sed turbinia/config/turbinia_config_tmpl.py > conf/turbinia.conf
