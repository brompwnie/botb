package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"gopkg.in/yaml.v2"
)

var verbosePtr, huntSockPtr, huntHttpPtr, huntDockerPtr, toJsonPtr, autopwnPtr, cicdPtr, reconPtr, metaDataPtr, findDockerdPtr, scrapeGcpMeta, alwaysSucceedPtr, k8secrets, pwnKeyctl *bool

var validSocks []string

var exitCode int
var keyMin, keyMax *int
var pathPtr, aggressivePtr, hijackPtr, wordlistPtr, endpointList, pushToS3ptr, s3BucketPtr, awsRegionPtr, cgroupPtr, configPtr, revDNSPtr *string

type IpAddress struct {
	Address string
}

type Interface struct {
	Name      string
	Addresses []IpAddress
}

type Config struct {
	Payload       string
	Verbose       bool
	Cicd          bool
	AlwaysSucceed bool
	Endpoints     string
	WordList      string
	Path          string
	Mode          string
	Min           int
	Max           int
}

func main() {
	fmt.Println("[+] Break Out The Box")
	exitCode = 0
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	pathPtr = flag.String("path", "/", "Path to Start Scanning for UNIX Domain Sockets")
	verbosePtr = flag.Bool("verbose", false, "Verbose output")
	huntSockPtr = flag.Bool("find-sockets", false, "Hunt for Available UNIX Domain Sockets")
	huntHttpPtr = flag.Bool("find-http", false, "Hunt for Available UNIX Domain Sockets with HTTP")

	autopwnPtr = flag.Bool("autopwn", false, "Attempt to autopwn exposed sockets")
	cicdPtr = flag.Bool("cicd", false, "Attempt to autopwn but don't drop to TTY,return exit code 1 if successful else 0")
	reconPtr = flag.Bool("recon", false, "Perform Recon of the Container ENV")
	metaDataPtr = flag.Bool("metadata", false, "Attempt to find metadata services")
	aggressivePtr = flag.String("aggr", "nil", "Attempt to exploit RuncPWN")
	hijackPtr = flag.String("hijack", "nil", "Attempt to hijack binaries on host")
	wordlistPtr = flag.String("wordlist", "nil", "Provide a wordlist")
	endpointList = flag.String("endpoints", "nil", "Provide a textfile with endpoints to use for test")
	findDockerdPtr = flag.Bool("find-docker", false, "Attempt to find Dockerd")
	pushToS3ptr = flag.String("s3push", "nil", "Push a file to S3 e.g Full command to push to https://YOURBUCKET.s3.eu-west-2.amazonaws.com/FILENAME would be: -region eu-west-2 -s3bucket YOURBUCKET -s3push FILENAME")
	s3BucketPtr = flag.String("s3bucket", "nil", "Provide a bucket name for S3 Push")
	awsRegionPtr = flag.String("region", "nil", "Provide a AWS Region e.g eu-west-2")
	scrapeGcpMeta = flag.Bool("scrape-gcp", false, "Attempt to scrape the GCP metadata service")
	cgroupPtr = flag.String("pwn-privileged", "nil", "Provide a command payload to try exploit --privilege CGROUP release_agent's")
	alwaysSucceedPtr = flag.Bool("always-succeed", false, "Always set BOtB's Exit code to Zero")
	configPtr = flag.String("config", "nil", "Load config from provided yaml file")
	revDNSPtr = flag.String("rev-dns", "nil", "Perform reverse DNS lookups on a subnet. Parameter must be in CIDR notation, e.g., -rev-dns 192.168.0.0/24")
	k8secrets = flag.Bool("k8secrets", false, "Identify and Verify K8's Secrets")

	pwnKeyctl = flag.Bool("pwnKeyctl", false, "Abuse keyctl syscalls and extract data from Linux Kernel keyrings")
	keyMin = flag.Int("keyMin", 1, " Minimum key id range (default 1)")
	keyMax = flag.Int("keyMax", 100000000, " Maximum key id range (default 100000000) and max system value is 999999999")

	flag.Parse()

	if *configPtr != "nil" {
		//prep the config with some defaults
		cfg := Config{Path: ".", Verbose: false, Cicd: false, Payload: "nil"}

		cfg, err := loadConfig(*configPtr, cfg)
		if err != nil {
			fmt.Println("[ERROR] Loading config", err)
			return
		}
		*verbosePtr = cfg.Verbose
		runCfgArgs(cfg)

	} else {
		runCMDArgs()
	}

	fmt.Println("[+] Finished")
	if *alwaysSucceedPtr {
		os.Exit(0)
	} else {
		os.Exit(exitCode)
	}
}

func loadConfig(configPath string, config Config) (Config, error) {
	fmt.Println("[+] Loading Config:", configPath)
	source, err := ioutil.ReadFile(configPath)
	if err != nil {
		return config, err
	}
	err = yaml.Unmarshal(source, &config)
	if err != nil {
		return config, err
	}
	return config, nil
}

func runCfgArgs(cfg Config) {
	switch cfg.Mode {
	case "find-sockets":
		findDomainSockets(cfg.Path)
	case "find-http":
		findHttpSockets(cfg.Path)
	case "find-docker":
		findDockerD()
	case "metadata":
		checkMetadataServices(cfg.Endpoints)
	case "autopwn":
		autopwn(cfg.Path, cfg.Cicd)
	case "recon":
		fmt.Println("[+] Performing Container Recon")
		checkProcEnviron(cfg.WordList)
		checkEnvVars(cfg.WordList)
	case "scrape-gcp":
		scrapeMetadataEndpoints(cfg.Endpoints)
	case "hijack":
		hijackBinaries(cfg.Payload)
	case "aggr":
		runcPwn(cfg.Payload)
	case "pwn-privileged":
		abuseCgroupPriv(cfg.Payload)
	case "pwn-keyctl":
		pwnKeyCtl(cfg.Max, cfg.Min)
	default:
		fmt.Println("[!] Invalid mode provided")
	}
}

func runCMDArgs() {

	if *pwnKeyctl {
		pwnKeyCtl(*keyMin, *keyMax)
	}

	if *k8secrets {
		idenitfyVerifyK8Secrets()
	}

	if *cgroupPtr != "nil" {
		abuseCgroupPriv(*cgroupPtr)
	}

	if *scrapeGcpMeta {
		scrapeMetadataEndpoints(*endpointList)
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
		findHttpSockets(*pathPtr)
	}

	if *hijackPtr != "nil" {
		hijackBinaries(*hijackPtr)
	}

	if *aggressivePtr != "nil" {
		runcPwn(*aggressivePtr)
	}

	if *reconPtr {
		fmt.Println("[+] Performing Container Recon")
		checkProcEnviron(*wordlistPtr)
		checkEnvVars(*wordlistPtr)
	}

	if *metaDataPtr {
		checkMetadataServices(*endpointList)
	}

	if *autopwnPtr {
		autopwn(*pathPtr, *cicdPtr)
	}

	if *huntSockPtr {
		fmt.Println("[+] Hunting Down UNIX Domain Sockets from:", *pathPtr)
		sockets, _ := getValidSockets(*pathPtr)
		for _, element := range sockets {
			fmt.Println("[!] Valid Socket: " + element)
			exitCode = 1
		}
	}

	if *revDNSPtr != "nil" {
		reverseDNS(*revDNSPtr)
	}
}
