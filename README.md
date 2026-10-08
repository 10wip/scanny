# Analyze and Extract API Keys ToolKit

## Installation
1. To install the program, you need to install Go on the machine:
> Debian/Ubuntu
> ```bash
> # Install Golang
> sudo apt-get update && sudo apt-get -y install golang-go
>
> # Check if Go has been properly installed
> go version
>
> # ex: go version go1.18.1 linux/amd64
> ```
2. Install the libraries necessary for the program to function properly
> ```bash 
> go get github.com/PuerkitoBio/goquery
> go get github.com/valyala/fasthttp
> go get github.com/fatih/color
> go get golang.org/x/net/html
> ```

## Configuration
Before using the program, you need to know how to configure it
> The software architecture is structured as follows:
```bash
📂 dist/
└── * (git dumps)
📂 keys/
└── 📜 *.txt (retrieved keys)
📂 src/
└── 💻 gitdumper.go
📜 domains.txt
📜 paths.txt
💻 main.go
📋 go.mod
📋 go.sum
```
It's possible to add domains and paths in `domains.txt` and `paths.txt`, you just need to list them line by line.
Modifying domains allows you to add new domain names and IPs.
Modifying paths allows you to add new endpoints to analyze.
It's also possible to modify the timeout (maximum wait time in case of no server response), to do this you need to go to `main.go` at line `75`:
```go
timeout           = 1000.0
```
The timeout is represented in milliseconds, so here there's a maximum response time of one second. You can modify it as you wish, but setting it too low with a poor internet connection could give no positive results.

## Usage
To use the program, simply run:
```bash
go run main.go
```
To compile the program, just execute this command:
```bash
go build main.go
# Execute the program:
./main
```

### Available parameters:
* `threads`: Allows you to choose the number of threads (parallel domain analysis), default is 50
* `verbose`: Activates all logs to debug the software more easily 
```bash
go run main.go -thread 500 -verbose
./main -thread 500 -verbose
```