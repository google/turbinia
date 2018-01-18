#!/bin/bash
# 
# This is a helper script to run arbitrary commands as the turbinia user within
# the virtualenv.  If the user is not correct it will re-execute the script as
# the correct user.

user="turbinia"
turbiniaenv="/home/turbinia/turbinia-env"

export GOOGLE_APPLICATION_CREDENTIALS="/home/turbinia/turbinia-service-account-creds.json"

if [[ $(id -u) -ne $(id -u $user) ]] ; then
	sudo su - $user -c "$0 \"$@\""
	exit $?
fi

. $turbiniaenv/bin/activate

bash -c "$@"
