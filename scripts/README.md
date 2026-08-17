# Scripts

## Documentation screenshots

`screenshots.mjs` photographs every documented page at three widths in both
themes, and `seed-demo.py` fills a database with the demo data they show. The
result lands in `docs/public/screenshots/`.

The capture needs a browser, so it runs inside a container.

### 1. Start a server and seed it

Build an image with the version stamped, so the panel shows a real version
rather than `dev`. Pass the number without a leading `v`, since the interface
adds one.

```bash
docker build --build-arg VERSION=0.9.4 -t gk-shots .
mkdir -p /tmp/gk-shots/data && chmod 777 /tmp/gk-shots/data

docker run -d --name gk-shots -p 18282:8282 -p 18283:8283 \
  -v /tmp/gk-shots/data:/data \
  -e BASE_URL=http://localhost:18282 \
  -e ADMIN_URL=http://localhost:18283 \
  -e SECRET_KEY=0123456789abcdef0123456789abcdef \
  gk-shots

sleep 5 && docker stop gk-shots
docker run --rm -v /tmp/gk-shots/data:/data alpine chmod 666 /data/gatekeeper.db
python3 scripts/seed-demo.py /tmp/gk-shots/data/gatekeeper.db /tmp/gk-shots/cookies.json
docker start gk-shots
```

### 2. Capture

```bash
cp scripts/screenshots.mjs /tmp/gk-shots/

docker run --rm --network host -v /tmp/gk-shots:/work \
  -e OUT_DIR=/work/out -e COOKIES=/work/cookies.json \
  --entrypoint sh zenika/alpine-chrome:with-puppeteer \
  -c "ln -sfn /usr/src/app/node_modules /work/node_modules && node /work/screenshots.mjs"
```

The symbolic link is needed because the script is an ES module, so it looks for
its dependencies next to itself rather than in the working directory.

### 3. Compress and install

Screenshots are committed, so they are reduced first. This roughly quarters the
size with no visible difference.

```bash
docker run --rm -v /tmp/gk-shots/out:/imgs alpine sh -c \
  "apk add --no-cache pngquant >/dev/null && cd /imgs && pngquant --quality=65-88 --speed 1 --force --ext .png *.png"

cp /tmp/gk-shots/out/*.png docs/public/screenshots/
docker rm -f gk-shots && docker rmi gk-shots
```

### Naming

Files are named `<page>[-tablet|-mobile]-<light|dark>.png`. The documentation
picks the variant matching the reader's theme, so both are always needed.

Phone and tablet captures are limited to the pages where the layout genuinely
changes, which is set by `mobilePages` and `tabletPages` in the script. Adding
every page at every width produces near identical images and a heavier
repository.
