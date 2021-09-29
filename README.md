# Controller of aries-cloudagent-python (Go version)
- Implementation of [Hyperledger Aries Cloud Agent - Python(ACA-Py)](https://github.com/hyperledger/aries-cloudagent-python) compatible Controller.

## Repository structure
The controller implementation is in directory [alice](./alice) & [faber](./faber). 

Repository structure details:
```
/
├── alice/       # Alice (Holder) controller implementation
├── faber/       # Faber (Issuer&Verifier) controller implementation
├── util/        # Common utility functions
└── docker/      # docker-compose.yml to run ACA-Py agent
```

## Prerequisite 
- Go version 1.16 or higher for source compilation
- Docker & docker-compose for running ACA-Py
---

## Steps to run demo
### Run cloud agency with multitenancy support
- ACA-Py agency opens 8020 port (endpoint) and 8021 port (admin). 
Check admin (swagger API) http://localhost:8021/api/doc
```
$ cd docker
$ docker-compose up --build
```

### Run Faber controller
- Faber controller opens 8040 port.
- It receives webhook message from Faber agent by POST http://localhost:8040/webhooks/topic/{topic}/ 
- Also, It presents invitation-url by GET http://localhost:8040/invitation-url
- Detailed configuration is in [faber-config.yml](./faber/faber-config.yml)
```
$ cd faber
$ go build
$ ./faber
```

### Run Alice controller
- Alice controller opens 8050 port. 
- It receives webhook message from alice agent by POST http://localhost:8050/webhooks/topic/{topic}/ 
- When alice controller starts, it gets invitation from faber controller and proceeds connection, credential and proof(presentation) sequentially.
- Detailed configuration is in [alice-config.yml](./alice/alice-config.yml)
```
$ cd alice
$ go build
$ ./alice
```

## Work flow
### Provision (Issuer or Holder)
| Public API | Issuer API | Steward API |
|---|---|---|
| POST /multitenancy/wallet |  |  |
|  | POST /wallet/did/create |  |
|  |  | POST /ledger/register-nym |
|  | POST /wallet/did/public |  |
- Holder only needs POST /multitenancy/wallet.

### Credential Preparation (Issuer)
| Issuer API | Issuer webhook (topic, state) |
|---|---|
| POST /schemas |  |
| POST /credential-definitions | revocation_registry, init generated posted active |

### Connection
| Issuer API | Holder API | Issuer webhook (topic, state) | Holder webhook (topic, state) |
|---|---|---|---|
| POST /connections/create-invitation |  |  |  |
|  | POST /connections/receive-invitation |  | connections, invitation |
|  | **auto** POST /connections/{conn_id}/accept-invitation | connections, request | connections, request |
| **auto** POST /connections/{conn_id}/accept-request |  | connections, response | connections, response |
|  | **auto** POST /connections/{conn_id}/send-ping | connections, active | connections, active |

### Issue Credential
| Issuer API | Holder API | Issuer webhook (topic, state) | Holder webhook (topic, state) |
|---|---|---|---|
|  | POST /issue-credential/send-proposal | issue_credential, proposal_received | issue_credential, proposal_sent |
| POST /issue-credential/records/{credExId}/send-offer |  | issue_credential, offer_sent | issue_credential, offer_received |
|  | POST /issue-credential/records/{credExId}/send-request | issue_credential, request_received | issue_credential, request_sent |
| **auto** POST /issue-credential/records/{credExId}/issue |  | issue_credential, credential_issued | issue_credential, credential_received |
|  |  | issuer_cred_rev, issued |  |
|  | **auto** POST /issue-credential/records/{credExId}/store | issue_credential, credential_acked | issue_credential, credential_acked |

### Presentation
| Issuer API | Holder API | Issuer webhook (topic, state) | Holder webhook (topic, state) |
|---|---|---|---|
|  | POST /present-proof/send-proposal | present_proof, proposal_received | present_proof, proposal_sent |
| POST /present-proof/send-request |  | present_proof, request_sent | present_proof, request_received |
|  | GET /present-proof/records/{presExId}/credentials |  |  |
|  | POST /present-proof/records/{presExId}/send-presentation | present_proof, presentation_received | present_proof, presentation_sent |
| **auto** POST /present-proof/records/{presExId}/verify-presentation |  | present_proof, verified | present_proof, presentation_acked |
