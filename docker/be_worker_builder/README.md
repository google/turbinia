To build, execute ./run.sh. This will:
* pull the ubuntu-essential image
* Create a new be-builder container with build prereqs
* build bulk_extractor w/ hashdb & lightgrep
* install pyrun, a mostly-static minimal python
* install celery & turbinia
* install dockerize, a python script to create minimal docker containers
* Run dockerize, outputting to ./out
* Strip all of the binaries here
* Build the new be-worker from ./out