module github.com/akto-api-security/api-gateway-logging

go 1.23.3

require (
	github.com/akto-api-security/api-gateway-logging/trafficUtil v0.0.0-00010101000000-000000000000
	github.com/aws/aws-sdk-go-v2 v1.41.1
	github.com/aws/aws-sdk-go-v2/config v1.29.0
	github.com/aws/aws-sdk-go-v2/credentials v1.17.53
	github.com/aws/aws-sdk-go-v2/service/apigateway v1.38.4
	github.com/aws/aws-sdk-go-v2/service/apigatewayv2 v1.33.5
	github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs v1.45.5
	github.com/aws/aws-sdk-go-v2/service/sts v1.33.8
	github.com/yinxulai/go-jsonrepair v0.0.0-20251224095639-b27538566d90
)

require (
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.6.7 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.24 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.17 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.17 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.12.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.12.9 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.24.10 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.28.9 // indirect
	github.com/aws/smithy-go v1.24.0 // indirect
	github.com/klauspost/compress v1.15.9 // indirect
	github.com/pierrec/lz4/v4 v4.1.15 // indirect
	github.com/segmentio/kafka-go v0.4.47 // indirect
)

replace github.com/akto-api-security/api-gateway-logging/trafficUtil => ./trafficUtil

replace github.com/akto-api-security/api-gateway-logging/accountconfig => ./accountconfig
