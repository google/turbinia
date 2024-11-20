FROM --platform=linux/amd64 ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 
ARG PPA_TRACK=stable

RUN apt-get update && apt-get -y upgrade && apt-get -y install \
    apt-transport-https \
    apt-utils \
    ca-certificates \
    curl \
    git \
    gpg \
    john \
    john-data \
    libleveldb1d \
    libleveldb-dev \
    libssl-dev \
    libterm-readline-gnu-perl \
    libtool \
    lvm2 \
    pocl-opencl-icd \
    p7zip-full \
    pkg-config \
    python3-pip \
    python3.12-venv \
    software-properties-common \
    sudo \
    testdisk \
    tox \
    wget \
    && apt-get clean && rm -rf /var/cache/apt/* /var/lib/apt/lists/*

# Install various packages from the GIFT PPA
#   bulkextractor
#   docker-explorer
#   Sleuthkit
RUN add-apt-repository -y ppa:gift/$PPA_TRACK
RUN apt-get update && apt-get -y install \
    bulk-extractor \
    docker-explorer-tools \
    libbde-tools \
    libfsapfs-tools \
    libluksde-tools \
    sleuthkit \
    libewf-tools \
    && apt-get clean && rm -rf /var/cache/apt/* /var/lib/apt/lists/*

# Add turbinia user to system and sudoers
RUN useradd -r -s /sbin/nologin -G disk,sudo -u 999 turbinia
RUN echo "turbinia ALL = (root) NOPASSWD: ALL" > /etc/sudoers.d/turbinia
RUN echo "Defaults secure_path=\"/home/turbinia/.venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"" >> /etc/sudoers.d/turbinia

# Install yara rules and fraken binary.
RUN cd /opt \
    && git clone https://github.com/Neo23x0/signature-base.git --depth=1\
    && sudo chown -R turbinia:turbinia /opt/signature-base \
    && sudo git config --global --add safe.directory /opt/signature-base \
    && find /opt/signature-base -type f -not -path '*.git/*' -not -iname '*.yar' -not -iname '*.yara' -not -iname 'file-type-signatures.txt' -delete
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
ENV PATH="$PATH:/home/turbinia/hashcat-6.2.6/"

# Get a decent password list for john/hashcat
RUN cd /home/turbinia && echo "" > password.lst
RUN cd /home/turbinia && curl -s https://raw.githubusercontent.com/danielmiessler/SecLists/285474cf9bff85f3323c5a1ae436f78acd1cb62c/Passwords/UserPassCombo-Jay.txt >> password.lst
RUN cd /home/turbinia && curl -s https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt >> password.lst
RUN cp /home/turbinia/password.lst /root/
RUN echo ':\nd' > /home/turbinia/turbinia-password-cracking.rules

# Copy Kubernetes support tool to home folder
COPY --chown=turbinia:turbinia k8s/tools/check-lockfile.py /home/turbinia/check-lockfile.py

# Set the working directory
WORKDIR /home/turbinia

# Copy only requirements, to cache them in docker layer
COPY --chown=turbinia:turbinia ./pyproject.toml ./poetry.toml ./poetry.lock /home/turbinia/

# Install poetry
RUN python3 -m venv .venv
ENV PATH="/home/turbinia/.local/bin:/home/turbinia/.venv/bin:$PATH" \
    VIRTUAL_ENV=/home/turbinia/.venv
RUN python3 -m pip install poetry

# Install dependencies using Poetry
RUN poetry install --no-interaction --no-ansi -E worker --with test --no-root
RUN poetry run python3 -m pip install impacket --no-deps

# Copy the source directory to the container
COPY --chown=turbinia:turbinia . /home/turbinia/

RUN poetry install --no-interaction --no-ansi -E worker --with test

# We need to install the current dev version of turbinia-api-lib for the cli tool test in case the API client changes
RUN cd turbinia/api/client && poetry install
CMD ["/bin/bash"]
