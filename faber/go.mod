module github.com/sktston/acapy-controller-go/faber

go 1.14

require (
	github.com/gin-gonic/gin v1.6.3
	github.com/sktston/acapy-controller-go/utils v0.0.0-00010101000000-000000000000
	github.com/smartystreets/goconvey v1.6.4 // indirect
	github.com/tidwall/gjson v1.6.0
	github.com/withmandala/go-log v0.1.0
)

replace github.com/sktston/acapy-controller-go/utils => ../utils
