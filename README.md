# Python TEE Simulator Template

This is a simple template for a Python application that uses the TEE Simulator SDK.

## Getting Started

1. Run the TEE Remote Attestation Simulator:

```bash
docker run --rm -p 8090:8090 phalanetwork/tappd-simulator:latest
```

2. Build the python docker container:

```bash
docker build -t your-dapp:latest .
```

3. Run the docker container:

```bash
docker run --rm -p 3000:3000 your-dapp:latest
```

