// nmap alternative in Go
// it will be a simple port scanner
// cmd line arguments -> host, ports

package main

import (
	"flag"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
)

var (
	host      string
	ports     string
	portStart int = 0
	portStop  int = 0
)

var openPorts = make(chan int, 65535)

func scan(host string, port int, wg *sync.WaitGroup) {
	defer wg.Done()
	// fmt.Println("[+] Checking open port:", port)
	conn, err := net.Dial("tcp", host+":"+strconv.Itoa(port))
	if err == nil {
		fmt.Println("[+] Found open port:", port)
		openPorts <- port
		defer conn.Close() // in a scenario like a panic, it will close the connection
	}
}

func main() {
	// take cmd line arguments
	flag.StringVar(&host, "host", "127.0.0.1", "host to scan (e.g. localhost)")
	flag.StringVar(&ports, "ports", "all", "ports range to scan (e.g. 25-1024 or none for all)")
	flag.Parse()
	fmt.Println(host, ports)

	// if ports is specified, split it and get start and stop ports
	if ports != "all" {
		portsSplit := strings.Split(ports, "-")
		if portsSplit == nil {
			fmt.Println("[-] Invalid ports range: Please specify ports as 'start-stop'")
			return
		}
		portStart, _ = strconv.Atoi(portsSplit[0])
		portStop, _ = strconv.Atoi(portsSplit[1])
	} else { // if ports is not specified, scan all ports
		portStart = 1
		portStop = 65535
	}
	fmt.Println("Scanning host:", host)
	fmt.Println("Scanning ports:", portStart, "-", portStop)

	var wg sync.WaitGroup
	for port := portStart; port <= portStop; port++ {
		//@TODO: SYN SCAN -> send SYN wait SYN-ACK then send RST, with -syn flag
		wg.Add(1)
		go scan(host, port, &wg)
	}
	wg.Wait()
	close(openPorts)
	fmt.Println("[+] Number of open ports:", len(openPorts))
}
