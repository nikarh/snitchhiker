#!/usr/bin/env bash
# Builds the relay's container image from a static (musl) snitchhiker-relay binary, then checks it runs as the docs
# say to run it (read-only, every capability dropped, no new privileges) and reports healthy:
#
#   scripts/relay-image.sh <static relay binary> <image tag> [CA bundle]
#
# The image is FROM scratch: the binary, a CA bundle (the push gateway calls FCM over HTTPS), the packaged
# relay.toml (plain HTTP on port 80, every other key at its default: mount your own over it), and the certificate
# directory, writable by any user (a fresh named volume mounted there inherits that). It runs as nobody.
set -euo pipefail
cd "$(dirname "$0")/.."
binary=${1:?usage: scripts/relay-image.sh <static relay binary> <image tag> [CA bundle]}
tag=${2:?the image tag}
ca=${3:-/etc/ssl/certs/ca-certificates.crt}

if ! file "${binary}" | grep -q "statically linked\|static-pie linked"; then
  echo "${binary} isn't statically linked: build it for the musl target" >&2
  exit 1
fi
context=$(mktemp -d)
trap 'rm -rf "${context}"' EXIT
install -D -m 755 "${binary}" "${context}/rootfs/usr/bin/snitchhiker-relay"
install -D -m 644 "${ca}" "${context}/rootfs/etc/ssl/certs/ca-certificates.crt"
install -D -m 644 dist/relay/relay.toml "${context}/rootfs/etc/snitchhiker/relay.toml"
install -d -m 1777 "${context}/rootfs/var/lib/snitchhiker-relay/certs"
cat > "${context}/Containerfile" <<'IMAGE'
FROM scratch
COPY rootfs/ /
USER 65534:65534
EXPOSE 80/tcp 443/tcp 7842/udp
VOLUME /var/lib/snitchhiker-relay
HEALTHCHECK --interval=30s --timeout=5s CMD ["/usr/bin/snitchhiker-relay", "healthcheck"]
ENTRYPOINT ["/usr/bin/snitchhiker-relay"]
IMAGE
docker build --quiet --file "${context}/Containerfile" --tag "${tag}" "${context}" > /dev/null

# As the docs run it: it must start, and its healthcheck pass, with nothing more.
name=snitchhiker-relay-check-$$
docker run --detach --name "${name}" --read-only --cap-drop=ALL --security-opt no-new-privileges "${tag}" > /dev/null
trap 'docker rm --force "${name}" > /dev/null 2>&1 || true; rm -rf "${context}"' EXIT
for _ in $(seq 30); do
  if docker exec "${name}" /usr/bin/snitchhiker-relay healthcheck > /dev/null 2>&1; then
    docker run --rm "${tag}" --version
    echo "${tag}: built and healthy"
    exit 0
  fi
  sleep 1
done
echo "${tag}: the relay didn't become healthy" >&2
docker logs "${name}" >&2
exit 1
