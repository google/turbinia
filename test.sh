curl https://raw.githubusercontent.com/obsidianforensics/hindsight/master/tests/fixtures/profiles/60/History > History
tar -vzcf /evidence/history.tgz History
python3 turbinia/turbiniactl.py compresseddirectory -l /evidence/history.tgz
python3 turbinia/turbiniactl.py -a status -r [request_id]
redis-cli
keys *