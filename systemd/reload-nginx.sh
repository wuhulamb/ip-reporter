#!/bin/sh
# certbot deploy hook: reload nginx after a certificate is renewed.
# Install as /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh
set -e
systemctl reload nginx
