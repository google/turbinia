# Build: docker build -t fraken -f tools/fraken/Dockerfile .
# Run: docker run -ti fraken fraken -rules /opt/signature-base -folder /
# Image: us-docker.pkg.dev/osdfir-registry/turbinia/release/fraken:latest

FROM golang:alpine AS fraken-builder
RUN apk add --no-cache -t .build-deps \
  autoconf \
  automake \
  bison \
  build-base \
  curl \
  file \
  file-dev \
  flex \
  git \
  jansson \
  jansson-dev \
  jansson-static \
  libc-dev \
  libmagic \
  libmagic-static \
  libtool \
  linux-headers \
  openssl \
  openssl-dev \
  openssl-libs-static \
  py3-setuptools \
  python3 \
  python3-dev \
  sudo

RUN set -x \
  && echo "Compiling Yara from source..."

# Fetch and compile libyara
RUN mkdir -p /opt/fraken/yara
WORKDIR /opt/fraken/yara
RUN cd /opt/fraken/yara && curl -s -L --retry 5 "$(curl -s -L --retry 5 https://api.github.com/repos/VirusTotal/Yara/releases/latest | sed -n 's/.*"tarball_url": "\(.*\)",.*/\1/p')"  | tar -xz --strip-components=1
RUN ./bootstrap.sh
RUN sync
RUN ./configure --with-crypto \
  --enable-magic \
  --enable-cuckoo
RUN make
RUN sudo make install

# Compile fraken statically
COPY tools/fraken/* /opt/fraken/
RUN cd /opt/fraken && GOOS=linux GOARCH=amd64 go build -a -v -ldflags="-linkmode=external -extldflags=-static" -installsuffix netgo -tags yara_static,osusergo,netgo -o fraken

FROM alpine:3.18.4 AS fraken
# Install yara rules and fraken binary.
RUN apk add --no-cache -t .build-deps git
RUN cd /opt \
    && git clone https://github.com/Neo23x0/signature-base.git \
    && find /opt/signature-base -type f -not -iname '*.yar' -not -iname '*.yara' -not -iname 'file-type-signatures.txt' -delete
COPY turbinia/config/rules/*.yar /opt/signature-base/yara/
#
COPY --from=fraken-builder /opt/fraken/fraken /bin/fraken
CMD ["fraken","-h"]
