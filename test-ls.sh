#!/bin/bash -e

cd "$(dirname "$0")"

USE_OPEN="true"
# USE_OPEN="false"

if ! [ -d test ]; then
    mkdir test
    dd if=/dev/urandom of=test/stek48.key bs=48 count=1
    dd if=/dev/urandom of=test/stek80.key bs=80 count=1
fi

if [ "$USE_OPEN" = "true" ]; then
    NAME="OLS"
    IMAGE=litespeedtech/openlitespeed
    SERVER_NAME="openlitespeed"
    CONF_FILE="test/config-ols"
else
    NAME="LS"
    IMAGE=litespeedtech/litespeed
    SERVER_NAME="litespeed"
    CONF_FILE="test/config-ls"
fi

python -m evaluate.util.config "$SERVER_NAME" one-server |  grep "# openlitespeed" -A 9999 > "$CONF_FILE"
chmod +r "$CONF_FILE"


docker run --rm -d \
    -v "$(pwd)/testcases/certs:/certs:ro" \
    -v "$(pwd)/testcases/sites:/sites:ro" \
    -v "$(pwd)/test/stek48.key:/stek.key:ro" \
    -v "$(pwd)/$CONF_FILE:/usr/local/lsws/conf/httpd_config.conf:ro" \
    --name "$NAME" \
    "$IMAGE"
    # -v "$(pwd)/test/lsws/conf/:/usr/local/lsws/conf/" \

docker inspect "$NAME" | grep IPAddress

LSADPATH='/usr/local/lsws/admin'
PW="admin"
docker exec ${NAME} su -s /bin/bash root -c \
    'if [ -e /usr/local/lsws/admin/fcgi-bin/admin_php ]; then \
    echo "admin:$('${LSADPATH}'/fcgi-bin/admin_php -q '${LSADPATH}'/misc/htpasswd.php '${PW}')" > '${LSADPATH}'/conf/htpasswd; \
    else echo "admin:$('${LSADPATH}'/fcgi-bin/admin_php5 -q '${LSADPATH}'/misc/htpasswd.php '${PW}')" > '${LSADPATH}'/conf/htpasswd; \
    fi';


stop_container() {
    echo "Stopping and removing container"
    docker rm -f "$NAME"
}

trap 'stop_container' SIGINT
echo "Following logs"
docker logs -f "$NAME"
