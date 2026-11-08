#!/bin/sh
set -eu

: "${DOMAIN:?Set DOMAIN in .env.proxy}"
: "${LE_EMAIL:?Set LE_EMAIL in .env.proxy}"
AUTH_MODE="${AUTH_MODE:-basic}"

case "$DOMAIN" in
  *[!A-Za-z0-9.-]*|.*|*-|'' ) echo "Invalid DNS name: $DOMAIN" >&2; exit 2 ;;
esac
case "$AUTH_MODE" in
  basic|oauth2) ;;
  *) echo "AUTH_MODE must be basic or oauth2" >&2; exit 2 ;;
esac

CERT_DIR="/etc/letsencrypt/live/$DOMAIN"
mkdir -p /etc/nginx/conf.d /var/www/certbot

write_bootstrap_config() {
  cat > /etc/nginx/conf.d/default.conf <<EOF
server {
    listen 80;
    server_name $DOMAIN;
    location ^~ /.well-known/acme-challenge/ {
        root /var/www/certbot;
        default_type text/plain;
    }
    location / { return 404; }
}
EOF
}

write_site_config() {
  sed "s|__DOMAIN__|$DOMAIN|g" "/opt/proxy/$AUTH_MODE.conf" \
    > /etc/nginx/conf.d/default.conf
}

write_bootstrap_config
nginx -t
nginx -g 'daemon off;' &
NGINX_PID=$!
cleanup() {
  kill "$NGINX_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

if [ ! -s "$CERT_DIR/fullchain.pem" ] || [ ! -s "$CERT_DIR/privkey.pem" ]; then
  certbot certonly \
    --webroot -w /var/www/certbot \
    --email "$LE_EMAIL" --agree-tos --no-eff-email --non-interactive \
    --cert-name "$DOMAIN" -d "$DOMAIN"
fi

write_site_config
nginx -t
nginx -s reload

(
  while :; do
    sleep 12h
    certbot renew --webroot -w /var/www/certbot --quiet \
      --deploy-hook 'nginx -s reload' || echo '[certbot] renewal check failed; will retry in 12 hours' >&2
  done
) &

wait "$NGINX_PID"
