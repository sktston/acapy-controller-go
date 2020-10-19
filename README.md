# Controller of aries-cloudagent-python (Go version)
- Implementation of [Hyperledger Aries Cloud Agent - Python(ACA-Py)](https://github.com/hyperledger/aries-cloudagent-python) compatible Controller.

- Porting the initial implementation of java by the [Dr. Baekje Seong](https://github.com/baegjae) in go language and all features  follow the [java version](https://github.com/sktston/acapy-controller-java)

## Repository structure
The controller implementation is in directory [alice](./alice) & [faber](./faber). 

Repository structure details:
```
/
├── alice/       # Alice (Holder) controller implementation
├── alice-multi/ # Multi-Alice (Multi-holder) controller implementation
├── faber/       # Faber (Issuer&Verifier) controller implementation
└── utils/       # Common utility functions 
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
$ mkdir ~/work
$ cd ~/work
$ git clone https://github.com/sktston/acapy-controller-java.git
$ cd ~/work/acapy-controller-java/docker
$ docker-compose up --build
```

### Run Faber controller
- Faber controller opens 8022 port.
- It receives webhook message from Faber agent by POST http://host.docker.internal:8022/webhooks/topic/{topic}/ 
- Also, It presents invitation by GET http://localhost:8022/invitation
- Detailed configuration is in [faber-config.json](./faber/faber-config.json)
```
$ mkdir ~/work
$ cd ~/work
$ git clone https://github.com/sktston/acapy-controller-go.git
$ cd ~/work/acapy-controller-go/faber
$ go build
$ ./faber
```

### Run Alice controller
- Alice controller opens 8023 port. 
- It receives webhook message from alice agent by POST http://host.docker.internal:8023/webhooks/topic/{topic}/ 
- When alice controller starts, it gets invitation from faber controller and proceeds connection, credential and proof(presentation) sequentially.
- Detailed configuration is in [alice-config.json](./alice/alice-config.json)
```
$ cd ~/work/acapy-controller-go/alice
$ go build
$ ./alice
```
### Separation of issuer and verifier
- In the above example, Faber executes issuer and verifier at the same time. However, in the real environment, issuer and verifier are separated.
- When executing Faber, you can specify whether to play only the issuer role or the verifier role with the '-i' option and the '-v' option.
- Set *IssuerWebhookUrl (ex: http://172.168.0.100:8022/webhooks)* and *VerifierWebhookUrl (ex: http://172.168.0.101:8032/webhooks)* of [faber-config.json](./faber/faber-config.json) file, respectively. 
- Also, set *IssuerContURL (ex: http://172.168.0.100:8022)* and *VerifierContURL (ex: http://172.168.0.101:8032)* of [alice-config.json](./alice/alice-config.json), respectively.
```
Terminal 1: Issuer
$ cd ~/work/acapy-controller-go/faber
$ ./faber -i

Terminal 2: Verifier
$ cd ~/work/acapy-controller-go/faber
$ ./faber -v

Terminal 3: Holder
$ cd ~/work/acapy-controller-go/alice
$ ./alice
```

### Run Multi-Alice controller

- Multiple holders (Alice) simultaneously execute issue and verify
- You can specify the number of holders and the total number of cycles (1 cycle = 1 issue & 1 verify) to be performed.
- Details of each parameter can be checked with 'alice-multi --help'.
```
Terminal 1: Issuer
$ cd ~/work/acapy-controller-go/faber
$ ./faber -i

Terminal 2: Verifier
$ cd ~/work/acapy-controller-go/faber
$ ./faber -v

Terminal 3: Multi-Holder 
(2 holder, 4 cycles -> 
Each holder performs 2 issue & verify)
$ cd ~/work/acapy-controller-go/alice-multi
$ ./alice-multi -n 2 -c 4 
```
