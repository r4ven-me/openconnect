## How to use docker image with openconnect server 1.4 and middle server functional

```bash
git clone https://github.com/r4ven-me/openconnect /tmp

cp -vr ./openconnect/src/server/v1.4-client /opt/openconnect

rm -rf /tmp/openconnect

cd /opt/openconnect

# Optional
vim .env

docker compose up
```
