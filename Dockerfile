FROM docker:28.1-dind

# Install Python and dependencies
RUN apk add --no-cache python3 py3-pip python3-dev gcc musl-dev libffi-dev openssl-dev

COPY requirements.txt requirements.txt
RUN pip3 install --no-cache-dir -r requirements.txt --break-system-packages

# Add your software
COPY evaluate evaluate

ENTRYPOINT ["sh", "-c", "dockerd & while ! docker info > /dev/null 2>&1; do sleep 1; done; sh"]
# CMD ["sh"]


