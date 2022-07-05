This is a multithreaded Yara scanner.  It supports rules that make use of the external variables defined in [signature-base](https://github.com/Neo23x0/signature-base), as well as having those variables defined in the metadata fields of the rules.

Its main use is as part of Turbinia but it can be compiled and used standalone.

Usage:
`./<binary> -folder <path to scan> -rules <path to rules>`

Thanks to [Loki](https://github.com/Neo23x0/Loki), [Kraken](https://github.com/botherder/kraken) and [go-yara](https://github.com/hillu/go-yara)

Needs Yara first, i.e:

```
sudo apt install gcc automake libtool make go-bindata dh-autoreconf libssl-dev
wget https://github.com/VirusTotal/yara/archive/refs/tags/v4.2.1.tar.gz
tar xvzf v4.2.1.tar.gz
cd yara-4.2.1
./bootstrap.sh
./configure
make && sudo make install && sudo ldconfig
```