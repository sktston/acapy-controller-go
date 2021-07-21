# Controller of aries-cloudagent-python (Go version)
- Implementation of [Hyperledger Aries Cloud Agent - Python(ACA-Py)](https://github.com/hyperledger/aries-cloudagent-python) compatible Controller.

- Porting the initial implementation of java by the [Dr. Baegjae Sung](https://github.com/baegjae) in go language and all features  follow the [java version](https://github.com/sktston/acapy-controller-java)

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
### Run Cloud Agents (Faber and Alice)
- Faber agent opens 8020 port (endpoint) and 8021 port (admin). 
Check admin (swagger API) http://localhost:8021
- Alice agent opens 8030 port (endpoint) and 8031 port (admin). 
Check admin http://localhost:8031
- Refer to [java implementation](https://github.com/sktston/acapy-controller-java)
```
mkdir ~/work
cd ~/work
git pull https://github.com/sktston/acapy-controller-java.git
cd ~/work/acapy-controller-java/docker
docker-compose up
```

### Run Faber Controller
- Faber controller opens 8022 port. 
- It receives webhook message from faber agent by POST http://localhost:8022/webhooks/topic/{topic}/ 
- Also, It presents invitation by GET http://localhost:8022/invitation
- Detailed configuration is in [faber-config.json](./faber/faber-config.json)
```
cd ~/work 
git pull https://github.com/sktston/acapy-controller-go.git
cd ~/work/acapy-controller-go/faber
go build
./faber
```

### Run Alice Controller
- Alice controller opens 8032 port. 
- It receives webhook message from alice agent by POST http://localhost:8032/webhooks/topic/{topic}/ 
- When alice controller starts, it gets invitation from faber controller and proceeds connection, credential and proof(presentation) sequentially.
- Detailed configuration is in [alice-config.json](./alice/alice-config.json)
```
cd ~/work 
cd ~/work/acapy-controller-go/alice
go build
./alice
```
