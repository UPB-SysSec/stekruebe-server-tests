FROM docker:28.1-dind

# Install Python and dependencies
RUN apk add --no-cache python3 py3-pip python3-dev gcc musl-dev libffi-dev openssl-dev curl

COPY requirements.txt requirements.txt
RUN pip3 install --no-cache-dir -r requirements.txt --break-system-packages

# Add your softwarecurl -k --resolve '*:443:172.18.0.2' https://a.com:443/
COPY evaluate evaluate
COPY testcases testcases

COPY create_certs.sh create_certs.sh
RUN chmod +x create_certs.sh
RUN ./create_certs.sh

# wrap the call "python3 -m evaluate"
ENTRYPOINT ["sh", "-c", "dockerd > /dev/null 2>&1 & while ! docker info > /dev/null 2>&1; do sleep 1; done; exec python3 -m evaluate \"$@\"", "--"]

# CMD ["sh"]


