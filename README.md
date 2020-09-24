# Controller of aries-cloudagent-python (Go version)
- Implementation of [Hyperledger Aries Cloud Agent - Python(ACA-Py)](https://github.com/hyperledger/aries-cloudagent-python) compatible Controller.

- Porting the initial implementation of java by the [Dr. Baekje Seong](https://github.com/baegjae) in go language and all features  follow the [java version](https://github.com/sktston/acapy-controller-java)

## Repository structure
The controller implementation is in directory [alice](./alice) & [faber](./faber). 

Repository structure details:
```
/
├── alice/   # Alice (Holder) controller implementation
├── faber/   # Faber (Issuer&Verifier) controller implementation
└── utils/   # Common utility functions 
```

## Prerequisite 
- Go version 1.14 or higher for source compilation
- Docker & docker-compose for running ACA-Py
---

## Steps to run demo
### Run cloud agency with multitenancy support
- ACA-Py agency opens 8020 port (endpoint) and 8021 port (admin). 
Check admin (swagger API) http://localhost:8021/api/doc
- Refer to [java implementation](https://github.com/sktston/acapy-controller-java)
```
mkdir ~/work
cd ~/work
git pull https://github.com/sktston/acapy-controller-java.git
cd ~/work/acapy-controller-java/docker
docker-compose up --build
```

### Run Faber controller
- Faber controller opens 8022 port.
- It receives webhook message from Faber agent by POST http://host.docker.internal:8022/webhooks/topic/{topic}/ 
- Also, It presents invitation by GET http://localhost:8022/invitation
- Detailed configuration is in [faber-config.json](./faber/faber-config.json)
```
mkdir ~/work
cd ~/work
git pull https://github.com/sktston/acapy-controller-go.git
cd ~/work/acapy-controller-go/faber
go build
./faber
```

### Run Alice controller
- Alice controller opens 8023 port. 
- It receives webhook message from alice agent by POST http://host.docker.internal:8023/webhooks/topic/{topic}/ 
- When alice controller starts, it gets invitation from faber controller and proceeds connection, credential and proof(presentation) sequentially.
- Detailed configuration is in [alice-config.json](./alice/alice-config.json)
```
cd ~/work/acapy-controller-go/alice
go build
./alice
```