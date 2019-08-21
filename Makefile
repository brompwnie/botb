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

all: clean build-linux

clean:
	@echo ">> removing previous builds"
	@rm -rf $(OUTPUTDIR)

$(GOPATH):
	GOPATH := $(HOME)/go

build-linux:
	@echo ">> running check for unused/missing packages in go.mod"
	@go mod tidy
	@echo ">> building binary"
	$(GOV111PREFIX) GOOS=linux GOARCH=amd64 go build -o $(OUTPUTDIR)/$(BINARY_NAME)-linux-amd64 ./
 