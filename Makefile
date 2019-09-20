# VERSION         :=      $(shell cat ./VERSION)
IMAGE_NAME      :=      golang:latest

all: install binaries

install:
	go build .
test:
	go test ./... -v

image:
	docker build . -t bob

binaries:
	gox -output="bin/{{.Dir}}_{{.OS}}_{{.Arch}}" -osarch="darwin/amd64 linux/386 linux/amd64"

# vandocker:
# 		docker build -f vandockerfile -t vandocker .

runvandocker:
	 docker run --rm -it -v /var/run/docker.sock:/tmp/thisisnotasocket.mock -v `pwd`:/app docker /bin/sh

# run:
# 	 docker run --rm -it -v /var/run/docker.sock:/var/run/docker.sock bob /bin/bash

run:
	 docker run --rm -it -v `pwd`:/app -v /var/run/docker.sock:/var/meh bob /bin/bash

runpriv:
	 docker run --rm --cap-add SYS_PTRACE -it -v `pwd`:/app -v /var/run/docker.sock:/var/meh bob /bin/bash

runpid:
	docker run -ti --rm --pids-limit="10" bob /bin/bash

runclean:
	 docker run -it bob /bin/bash
runtest: 
	docker run -it --rm -v `pwd`/bob:/bob -v /var/run/docker.sock:/var/meh bob /app/main -path=/ -cicd=true && echo $?
# runtest2: 
# 	docker run -it --rm --entrypoint "/bin/sh" ubuntu:latest
# runtest3: 
# 	docker run -it --rm -v /var/run/docker.sock:/var/meh --entrypoint "/bin/sh" ubuntu:latest
# .PHONY: install test fmt release


docker run --rm -it -v /var/run/docker.sock:/tmp/thisisnotasocket.mock -v `pw
d`:/app -e DOCKER_HOST='/tmp/thisisnotasocket.mock' golang /bin/sh