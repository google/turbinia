This is a multithreaded Yara scanner.  It supports rules that make use of the external variables defined in [signature-base](https://github.com/Neo23x0/signature-base), as well as having those variables defined in the metadata fields of the rules.

Its main use is as part of Turbinia but it can be compiled and used standalone.

Usage:
Run fraken from the docker image scanning a local folder

`docker run -v /my/folder/path:/data -ti fraken fraken -rules /opt/signature-base -folder /data`

Instead of a local image you can also use the public image located at 
`us-docker.pkg.dev/osdfir-registry/turbinia/release/fraken:latest`

Thanks to [Loki](https://github.com/Neo23x0/Loki), [Kraken](https://github.com/botherder/kraken) and [go-yara](https://github.com/hillu/go-yara)

Docker build:
Build the docker image using

`docker build -t fraken -f tools/fraken/Dockerfile .`



