## How to build docker image with openconnect server 1.4 with client

```bash
git clone https://github.com/r4ven-me/openconnect /tmp/openconnect

cp -vr /tmp/openconnect/src/server/v1.4-client /opt/openconnect

rm -rf /tmp/openconnect

cd /opt/openconnect

# Optional
vim .env

docker compose up
```
