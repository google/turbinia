### Build the image
```
docker build -t turbinia-api-server:dev .
```

### Base64 encode turbinia.conf
```
base64 -w 0 turbinia.conf > turbinia.conf.b64
```
-w 0 will output without column wrapping (not needed on OSX).

### Run the API server
```
docker run -ti \
-e TURBINIA_CONF=`cat turbinia.conf.b64` \
turbinia-api-server:dev
```
