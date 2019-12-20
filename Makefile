SHELL := /bin/bash
DIR := $(shell pwd)
BINARY_NAME := botb
OUTPUTDIR := ${DIR}/bin

.PHONY: all build-linux clean

GOV111PREFIX := 
GOV111 := $(shell expr `go version | cut -f2 -d.` \>= 11)
ifeq "$(GOV111)" ""
    GOV111PREFIX := env GO111MODULE=on 
else
	GOVERSION := $(shell expr `go version | cut -f2 -d.` \>= 11)
	ifeq "$(GOVERSION)" ""
		$(error must be running Go version 1.11 or newer, due to use of modules)
	endif
endif

all: clean build-linux64 build-darwin64 build-linux32 build-darwin32

clean:
	@echo ">> removing previous builds"
	@rm -rf $(OUTPUTDIR)

$(GOPATH):
	GOPATH := $(HOME)/go

build-linux64:
	@echo ">> running check for unused/missing packages in go.mod"
	@go mod tidy
	@echo ">> building Linux 64bit binary"
	$(GOV111PREFIX) GOOS=linux GOARCH=amd64 go build -o $(OUTPUTDIR)/$(BINARY_NAME)-linux-amd64 ./

build-darwin64:
	@echo ">> running check for unused/missing packages in go.mod"
	@go mod tidy
	@echo ">> building darwin 64bit binary"
	$(GOV111PREFIX) GOOS=darwin GOARCH=amd64 go build -o $(OUTPUTDIR)/$(BINARY_NAME)-darwin-amd64 ./


build-linux32:
	@echo ">> running check for unused/missing packages in go.mod"
	@go mod tidy
	@echo ">> building linux 32bit binary"
	$(GOV111PREFIX) GOOS=linux GOARCH=386 go build -o $(OUTPUTDIR)/$(BINARY_NAME)-linux-386 ./

build-darwin32:
	@echo ">> running check for unused/missing packages in go.mod"
	@go mod tidy
	@echo ">> building darwin 32bit binary"
	$(GOV111PREFIX) GOOS=darwin GOARCH=386 go build -o $(OUTPUTDIR)/$(BINARY_NAME)-darwin-386 ./
