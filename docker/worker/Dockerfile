# Build 1 - Turbinia Worker
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1
ARG PPA_TRACK=stable

RUN apt-get update && apt-get -y upgrade && apt-get -y install \
    apt-transport-https \
    apt-utils \
    ca-certificates \
    curl \
    git \
    john \
    john-data \
    libleveldb1d \
    libleveldb-dev \
    libssl-dev \
    libterm-readline-gnu-perl \
    lvm2 \
    pocl-opencl-icd \
    p7zip-full \
    python3-pip \
    software-properties-common \
    sudo \
    testdisk \
    wget \
    && apt-get clean && rm -rf /var/cache/apt/* /var/lib/apt/lists/*

RUN pip3 install pip --upgrade
RUN pip3 install poetry

# Install various packages from the GIFT PPA
#   bulkextractor
#   docker-explorer
#   Sleuthkit
#   bdemount, apfs and luks tools
RUN add-apt-repository -y ppa:gift/$PPA_TRACK
RUN apt-get update && apt-get -y install \
    bulk-extractor \
    docker-explorer-tools \
    libbde-tools \
    libfsapfs-tools \
    libluksde-tools \
    sleuthkit \
    && apt-get clean && rm -rf /var/cache/apt/* /var/lib/apt/lists/*

# Add turbinia user to system and sudoers
RUN useradd -r -s /sbin/nologin -G disk,sudo -u 999 turbinia
RUN echo "turbinia ALL = (root) NOPASSWD: ALL" > /etc/sudoers.d/turbinia
RUN echo "Defaults secure_path=\"/home/turbinia/.venv/bin:/opt/fraken:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"" >> /etc/sudoers.d/turbinia

# Install yara rules and fraken binary.
RUN cd /opt \
    && git clone https://github.com/Neo23x0/signature-base.git \
    && sudo chown -R turbinia:turbinia /opt/signature-base \
    && find /opt/signature-base -type f -not -iname '*.yar' -not -iname '*.yara' -not -iname 'file-type-signatures.txt' -delete
COPY turbinia/config/rules/*.yar /opt/signature-base/yara/
RUN mkdir -p /opt/fraken && chown -R turbinia:turbinia /opt/fraken
COPY --from=us-docker.pkg.dev/osdfir-registry/turbinia/release/fraken:latest --chown=turbinia:turbinia /bin/fraken /opt/fraken/fraken

# Install container-explorer
RUN wget -O /tmp/container-explorer-setup.sh https://raw.githubusercontent.com/google/container-explorer/main/script/setup.sh
RUN chmod +x /tmp/container-explorer-setup.sh
RUN sudo /tmp/container-explorer-setup.sh install

# Install docker CLI
RUN curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
RUN echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
RUN apt-get update
RUN apt-get -y install docker-ce-cli
RUN groupadd docker
RUN usermod -aG docker turbinia

# Setup turbinia user folders and permissions
RUN mkdir /etc/turbinia && mkdir -p /mnt/turbinia/ && mkdir -p /var/lib/turbinia/ \
    && mkdir -p /etc/turbinia/ && chown -R turbinia:turbinia /etc/turbinia/ \
    && mkdir -p /var/log/turbinia/ && chown -R turbinia:turbinia /mnt/turbinia/ \
    && chown -R turbinia:turbinia /var/lib/turbinia/ \
    && chown -R turbinia:turbinia /var/log/turbinia/ \
    && mkdir -p /home/turbinia && chown -R turbinia:turbinia /home/turbinia

# Install latest hashcat
RUN cd /home/turbinia \
    && wget https://hashcat.net/files/hashcat-6.2.6.7z \
    && 7z x hashcat-6.2.6.7z \
    && chown -R turbinia:turbinia /home/turbinia/hashcat-6.2.6/ \
    && cp /home/turbinia/hashcat-6.2.6/hashcat.bin /home/turbinia/hashcat-6.2.6/hashcat \
    && rm -f /home/turbinia/hashcat-6.2.6.7z
ENV PATH="/home/turbinia/hashcat-6.2.6/:$PATH"

# Get a decent password list for john/hashcat
RUN cd /home/turbinia && echo "" > password.lst
RUN cd /home/turbinia && curl -s https://raw.githubusercontent.com/danielmiessler/SecLists/285474cf9bff85f3323c5a1ae436f78acd1cb62c/Passwords/UserPassCombo-Jay.txt >> password.lst
RUN cd /home/turbinia && curl -s https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt >> password.lst
RUN cp /home/turbinia/password.lst /root/
RUN echo ':\nd' > /home/turbinia/turbinia-password-cracking.rules

# Copy Kubernetes support tool to home folder
COPY --chown=turbinia:turbinia k8s/tools/check-lockfile.py /home/turbinia/check-lockfile.py

# Drop privileges and set the working directory
USER turbinia
WORKDIR /home/turbinia

# Copy requirements and install dependencies to cache them in docker layer
COPY --chown=turbinia:turbinia ./pyproject.toml ./poetry.toml ./poetry.lock /home/turbinia/
RUN poetry install --no-interaction --no-ansi -E worker -E gcp --no-root
RUN poetry run pip3 install impacket --no-deps 
ENV PATH="/home/turbinia/.venv/bin:$PATH" \
    VIRTUAL_ENV=/home/turbinia/.venv

# Copy the source directory to the container
COPY --chown=turbinia:turbinia . /home/turbinia/
COPY --chown=turbinia:turbinia docker/worker/start.sh /home/turbinia/start.sh
RUN chmod +rwx /home/turbinia/start.sh

# Install Turbinia package -- will skip dependencies if installed
RUN poetry install --no-interaction --no-ansi -E worker -E gcp

CMD ["/home/turbinia/start.sh"]
# Expose Prometheus endpoint.
EXPOSE 9200/tcp
