#!/bin/sh
# Note: I've written this using sh so it works in the busybox container too

# USE the trap if you need to also do manual cleanup after the service is stopped,
#     or need to start multiple services in the one container
trap "echo TRAPed signal" HUP INT QUIT TERM
if [ "$DB" == "postgres" ]; then
  sudo -u postgres pg_ctl start -D $DB_DIR/pg
fi
# start service in background here
sudo php-fpm$PHP_VER
sudo nginx
/bin/sh
