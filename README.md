# server-tests
This artifact is a test suite for the handling of TLS session by various web servers. 
We analyze how behavior changes based on different SNI values, host headers and issuing and receiving virtual hosts. 

It is responsible for the results presented in Section 4, Table 1 of the paper.

## Usage
The artifact is a Python package that can be run from the command line, but we also provide a Docker-in-docker image for convenience.

### Running on Docker
Build the Docker image
```bash
docker build -t server-tests:latest .
```
The container executes the CLI tool, which offers different options.
You can ensure basic functionality by spawning a container with the following command, and then following the instructions printed by the script.
```bash
docker run --rm --name server-tests -it --privileged server-tests:latest deploy nginx one-server
docker exec server-tests <curl command printed by the script>
```
This should yield different dummy HTMLs based on the command you provide.

To run the full test suite, you can use the following command:
```bash
mkdir out
docker run --privileged --rm -it -v ./out:/out server-tests:latest evaluate --outdir out
``` 
This will run all tests and save the results in the `out` directory.

To verify the results against Table 1 of the paper, you can then run the following command:
```bash
docker run --privileged --rm -it -v ./out:/out server-tests:latest evaluate --outdir out
docker run --privileged --rm -it -v ./out:/out server-tests:latest postprocess out/results.jsonl
```

### Running on bare metal
- Python 3.12+
- pip
- OpenSSL-dev (with header files)
- Docker

For Ubuntu 25.04, you can install the dependencies with the following command:
```bash
sudo apt install python3-dev libssl-dev docker.io python3-full 
```bash
systemctl start docker.service
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```
To test basic functionality, you can run the following command:
```bash
python3 -m evaluate deploy nginx one-server
<curl command printed by the script>
```
To run the full test suite, you can use the following command:
```bash
python -m evaluate evaluate
```
To verify the results against Table 1 of the paper, you can then run the following command:
```bash
python -m evaluate postprocess results.jsonl
```

## Troubleshooting
### [Errno113] Host is unreachable/SocketTimeout for `closedlitespeed`
Our setup uses the trial version of LiteSpeed, which uses a license key that is bound to the IP address.
This should not be a problem for most users, but we encountered issues when running from our institutional network.
We were able to resolve this issue by using a VPN.