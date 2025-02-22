// nmap alternative in Go
// it will be a simple port scanner
// cmd line arguments -> host, ports, type

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/mostlygeek/arp"
	"github.com/phayes/freeport"
)

var (
	host      string
	ports     string
	scanType  string
	portStart int = 0
	portStop  int = 0
)

var openPorts = make(chan int, 65535)

func scan(handle *pcap.Handle, host string, port int, wg *sync.WaitGroup, scanType string) {
	defer wg.Done()
	if scanType == "tcp" {
		scanTcp(host, port)
	} else if scanType == "syn" {
		scanSyn(handle, host, port)
	}
}

func scanSyn(handle *pcap.Handle, host string, port int) {
	sendSynPacket(handle, host, port)
}

func sendSynPacket(handle *pcap.Handle, host string, port int) {
	rawPort, err := freeport.GetFreePort()
	if err != nil {
		log.Fatal(err)
	}

	buffer, err := createSynPacket(handle, host, port, rawPort)
	if err != nil {
		log.Fatal(err)
	}

	// send packet
	err = handle.WritePacketData(buffer.Bytes())
	if err != nil {
		log.Fatal(err)
	}
	func() {

		// start listening
		eth := &layers.Ethernet{}
		ip4 := &layers.IPv4{}
		tcp := &layers.TCP{}

		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, eth, ip4, tcp)

		for {

			data, _, err := handle.ReadPacketData()
			fmt.Println(err)
			if err == pcap.NextErrorTimeoutExpired {
				break
			} else if err == io.EOF {
				break
			} else if err != nil {
				// connection closed
				fmt.Printf("Packet read error: %s\n", err)
				continue
			}
			fmt.Println(data)

			decoded := []gopacket.LayerType{}
			if err := parser.DecodeLayers(data, &decoded); err != nil {
				continue
			}
			for _, layerType := range decoded {
				switch layerType {
				case layers.LayerTypeTCP:
					if tcp.DstPort != layers.TCPPort(rawPort) {
						continue
					}
					if tcp.SYN && tcp.ACK {
						fmt.Printf("[+] Port %d is OPEN on %s\n", tcp.SrcPort, host)
						return
					} else if tcp.RST {
						fmt.Printf("[-] Port %d is CLOSED on %s\n", tcp.SrcPort, host)
						return
					}
				}
			}
		}
	}()

	timer := time.AfterFunc(2*time.Second, func() { handle.Close() })
	defer timer.Stop()
}

func createSynPacket(handle *pcap.Handle, host string, port int, rawPort int) (gopacket.SerializeBuffer, error) {
	networkInterface, err := net.InterfaceByName("en0")
	if err != nil {
		log.Fatal(err)
	}
	//@ToDo: find gateway ip
	gateway := net.ParseIP("192.168.1.1")

	// need to get src mac and dst mac
	//@ToDo host habire aynıysa bunu surekli cagirmak mantikli degil
	hwaddr, err := getHwAddr(net.ParseIP(host), gateway, net.ParseIP("192.168.1.7"), networkInterface)
	if err != nil {
		log.Fatal(err)
	}

	// Ethernet Header
	ethLayer := layers.Ethernet{
		EthernetType: layers.EthernetTypeIPv4,
		SrcMAC:       net.HardwareAddr{0xa4, 0xcf, 0x99, 0x73, 0x24, 0x55},
		// DstMAC:       net.HardwareAddr{0x00, 0x0c, 0x29, 0x69, 0xe7, 0xea}, // burayi gateway'in mac adresi yapmazsan response donmez
		DstMAC: hwaddr,
	}

	// IP Header
	ipLayer := layers.IPv4{
		SrcIP:    net.ParseIP("192.168.1.7"),
		DstIP:    net.ParseIP(host),
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}

	// TCP Header
	tcpLayer := layers.TCP{
		SrcPort: layers.TCPPort(rawPort),
		DstPort: layers.TCPPort(port),
		SYN:     true,
		Window:  1024,
	}
	tcpLayer.SetNetworkLayerForChecksum(&ipLayer)

	// create packet
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err = gopacket.SerializeLayers(buffer, options, &ethLayer, &ipLayer, &tcpLayer)
	if err != nil {
		return nil, err
	}
	return buffer, nil
}

func getHwAddr(ip net.IP, gateway net.IP, srcIP net.IP, networkInterface *net.Interface) (net.HardwareAddr, error) {

	// grab mac from ARP table if we have it cached
	macStr := arp.Search(ip.String())
	if macStr != "00:00:00:00:00:00" {
		if mac, err := net.ParseMAC(macStr); err == nil {
			return mac, nil
		}
	}

	arpDst := ip
	if gateway != nil {
		arpDst = gateway
	}

	handle, err := pcap.OpenLive(networkInterface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	start := time.Now()

	// Prepare the layers to send for an ARP request.
	eth := layers.Ethernet{
		SrcMAC:       networkInterface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(networkInterface.HardwareAddr),
		SourceProtAddress: []byte(srcIP),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(arpDst),
	}

	buf := gopacket.NewSerializeBuffer()

	// Send a single ARP request packet (we never retry a send, since this
	options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, options, &eth, &arp); err != nil {
		return nil, err
	}
	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		return nil, err
	}

	// Wait 3 seconds for an ARP reply.
	for {
		if time.Since(start) > 3*time.Second {
			return nil, errors.New("timeout getting ARP reply")
		}
		data, _, err := handle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		} else if err != nil {
			return nil, err
		}
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
		if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
			arp := arpLayer.(*layers.ARP)
			if net.IP(arp.SourceProtAddress).Equal(arpDst) {
				return net.HardwareAddr(arp.SourceHwAddress), nil
			}
		}
	}
}

func scanTcp(host string, port int) {
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
	flag.StringVar(&scanType, "type", "tcp", "type of scan (e.g. tcp, syn)")
	flag.Parse()
	fmt.Println(host, ports)

	if scanType != "tcp" && scanType != "syn" {
		fmt.Println("[-] Invalid scan type: Please specify scan type as 'tcp' or 'syn'")
		return
	}

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

	handle, err := pcap.OpenLive("en0", 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	var wg sync.WaitGroup
	for port := portStart; port <= portStop; port++ {
		//@TODO: SYN SCAN -> send SYN wait SYN-ACK then send RST, with -syn flag
		wg.Add(1)
		go scan(handle, host, port, &wg, scanType)
	}
	wg.Wait()
	close(openPorts)
	fmt.Println("[+] Number of open ports:", len(openPorts))
}
