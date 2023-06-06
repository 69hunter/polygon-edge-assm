package ports

type IAwsSSMPort interface {
	GetValidatorKey(key string) (string, error)
	GetValidatorBlsKey(key string) (string, error)
	GetNetworkKey(id string) (string, error)
}
