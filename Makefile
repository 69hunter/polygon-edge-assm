all: 
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o main main.go
	chmod 655 main
	zip main.zip main
	mv main.zip artifacts/main.zip