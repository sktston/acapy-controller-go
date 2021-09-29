module github.com/sktston/acapy-controller-go/alice

go 1.16

replace github.com/sktston/acapy-controller-go/utils => ../utils

require (
	github.com/gin-contrib/logger v0.2.0
	github.com/gin-gonic/gin v1.7.2
	github.com/go-resty/resty/v2 v2.6.0
	github.com/rs/zerolog v1.23.0
	github.com/sktston/acapy-controller-go/utils v0.0.0-00010101000000-000000000000
	github.com/spf13/viper v1.9.0
	github.com/tidwall/gjson v1.8.1
	github.com/tidwall/sjson v1.1.7
)
