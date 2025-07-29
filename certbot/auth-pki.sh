#!/bin/ash
echo $CERTBOT_VALIDATION > /var/www/pki/.well-known/acme-challenge/$CERTBOT_TOKEN