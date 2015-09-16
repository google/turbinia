#!/bin/bash

docker rm ubuntu-essential-multilayer 2>/dev/null
set -ve
docker build -t textlab/ubuntu-essential-multilayer - <<'EOF'
FROM ubuntu:14.04
# Make an exception for apt: it gets deselected, even though it probably shouldn't.
RUN dpkg --clear-selections && echo apt install |dpkg --set-selections && \
    SUDO_FORCE_REMOVE=yes DEBIAN_FRONTEND=noninteractive apt-get --purge -y dselect-upgrade && \
    dpkg-query -Wf '${db:Status-Abbrev}\t${binary:Package}\n' |grep '^.i' |awk -F'\t' '{print $2 " install"}' |dpkg --set-selections && \
    rm -r /var/cache/apt /var/lib/apt/lists
EOF
TMP_FILE="`mktemp -t ubuntu-essential-XXXXXXX.tar.gz`"
docker run --rm -i textlab/ubuntu-essential-multilayer tar zpc --exclude=/etc/hostname \
  --exclude=/etc/resolv.conf --exclude=/etc/hosts --one-file-system / >"$TMP_FILE"
docker rmi textlab/ubuntu-essential-multilayer
docker import - textlab/ubuntu-essential-nocmd <"$TMP_FILE"
docker build -t textlab/ubuntu-essential - <<'EOF'
FROM textlab/ubuntu-essential-nocmd
CMD ["/bin/bash"]
EOF
docker rmi textlab/ubuntu-essential-nocmd
rm -f "$TMP_FILE"
