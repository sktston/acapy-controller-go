module github.com/sktston/acapy-controller-go/alice

go 1.16

replace github.com/sktston/acapy-controller-go/utils => ../utils

require (
	github.com/gin-gonic/gin v1.7.2
	github.com/google/uuid v1.3.0
	github.com/sktston/acapy-controller-go/utils v0.0.0-00010101000000-000000000000
	github.com/tidwall/gjson v1.8.1
	github.com/tidwall/sjson v1.1.7
)
