package main

import (
	"Repo/protocols"
	"fmt"
	"github.com/songgao/water"
	"log"
	"net"
	"os/exec"
)

func main() {
	//ifaces, err := net.Interfaces()
	//if err != nil {
	//	panic(err)
	//}
	//
	//for _, iface := range ifaces {
	//	fmt.Println(iface)
	//	if iface.Flags&net.FlagPointToPoint != 0 {
	//		fmt.Printf("Point-to-Point interface: %s\n", iface.Name)
	//	}
	//}
	// создаем tun интерфейс
	ifce, err := water.New(water.Config{
		DeviceType: water.TUN,
	})
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Interface Name:", ifce.Name())

	// назначаем ip для интерфейса
	cmd := exec.Command("ip", "addr", "add", "10.0.0.1/24", "dev", ifce.Name())
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("setting address for interface error: %s", string(out))
		log.Fatal(err)
	}

	// поднимаем интерфейс
	cmd = exec.Command("ip", "link", "set", "dev", ifce.Name(), "up")
	out, err = cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("up interface error: %s", string(out))
		log.Fatal(err)
	}

	// назначаем дефолтный роут через интерфейс
	cmd = exec.Command("ip", "route", "add", "default", "via", "10.0.0.1", "dev", ifce.Name())
	out, err = cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("set new interface as default error: %s", string(out))
		log.Fatal(err)
	}

	// направляем запросы первой половины IP-адресов в интерфейс (0.0.0.0 — 127.255.255.255)
	cmd = exec.Command("ip", "route", "add", "0.0.0.0/1", "dev", ifce.Name())
	out, err = cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("setting route traffic range 1 error: %s", string(out))
		log.Fatal(err)
	}

	// направляем запросы первой половины IP-адресов в интерфейс (128.0.0.0 — 255.255.255.255)
	cmd = exec.Command("ip", "route", "add", "128.0.0.0/1", "dev", ifce.Name())
	out, err = cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("setting route traffic range 2 error: %s", string(out))
		log.Fatal(err)
	}

	log.Println("Interface configured")

	packet := make([]byte, 1500) // MTU буфер

	for {
		n, err := ifce.Read(packet)
		if err != nil {
			log.Fatal(err)
		}
		// log.Printf("Got %d bytes: %x\n", n, packet[:n])

		parsedIpProtocol := protocols.ParseIPHeader(packet[:n])
		destIP := parsedIpProtocol.DestIP
		ip := net.IPv4(byte(destIP>>24), byte(destIP>>16), byte(destIP>>8), byte(destIP)).String()
		fmt.Println(ip)
	}
}
