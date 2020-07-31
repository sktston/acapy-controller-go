module github.com/sktston/acapy-controller-go/alice

go 1.14

replace github.com/sktston/acapy-controller-go/utils => ../utils

require (
	github.com/gin-gonic/gin v1.6.3
	github.com/sktston/acapy-controller-go/utils v0.0.0-00010101000000-000000000000
	github.com/tidwall/gjson v1.6.0
	github.com/tidwall/sjson v1.1.1
)
