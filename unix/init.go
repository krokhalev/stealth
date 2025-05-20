package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	cgroupPath = "/sys/fs/cgroup/myproxygroup"
	cgroupName = "myproxygroup"
	proxyIP    = "127.0.0.1"
	proxyPort  = "12345"
)

type pidsInfo struct {
	processName string
	pids        []string
}

// Init инитит cgroup и iptables
func (PC *ProxyClient) Init() {
	PC.WaitGroup.Add(1)
	defer PC.Cleanup()

	// 1. Создаем cgroup
	err := PC.createCgroup()
	if err != nil {
		PC.ErrChan <- fmt.Errorf("failed to create cgroup: %v", err)
		return
	}
	PC.Logger.Infof("[+] Created cgroup: %s\n", cgroupPath)

	// 2. Создаем iptables
	err = PC.applyIptablesRules()
	if err != nil {
		PC.ErrChan <- fmt.Errorf("failed to apply iptables rule: %v", err)
		return
	}
	PC.Logger.Info("[+] Applied iptables rules")

	PC.InitChan <- struct{}{}

	// 3. Находим PIDs по имени процесса
	// Если процесс создает новый подпроцесс, так же находим его и передаем в cgroup
	processNames := []string{"discord", "brave"}
	pidsChan := make(chan pidsInfo, len(PC.ProcessNames))
	for _, name := range processNames {
		go PC.findPIDs(name, pidsChan)
	}

	// 4. Добавляем PIDs в cgroup
	go PC.addPIDToCgroup(pidsChan)

	// 5. Ожидаем завершения
	<-PC.Ctx.Done()
	PC.Logger.Info("[!] Caught termination signal")
}

// Cleanup чистит crgoup и iptables
func (PC *ProxyClient) Cleanup() {
	// 0. Чистим cgroup и iptables
	// todo: придумать нормальный путь для удаления сигруппы
	//if err := os.RemoveAll(cgroupPath); err != nil {
	//	log.Printf("[-] Failed to remove cgroup dir: %v", err)
	//} else {
	//	fmt.Println("[+] Removed cgroup directory")
	//}
	if err := PC.disableRules(); err != nil {
		PC.Logger.Errorf("[-] Failed to disable iptables: %v", err)
	} else {
		PC.Logger.Info("[+] Disabled iptables")
	}
	PC.WaitGroup.Done()
}

// createCgroup создает директорию cgroup
func (PC *ProxyClient) createCgroup() error {
	err := os.MkdirAll(cgroupPath, 0755)
	if err != nil && !os.IsExist(err) {
		return err
	}
	return nil
}

// findPIDs ищет PIDs процесса по имени
func (PC *ProxyClient) findPIDs(processName string, pidsChan chan pidsInfo) {
	for {
		select {
		case <-PC.Ctx.Done():
			return
		default:
			cmd := exec.Command("pgrep", "-f", processName)
			output, err := cmd.Output()
			if err != nil {
				time.Sleep(1 * time.Second)
				continue
			}
			pids := strings.Fields(string(output))
			if len(pids) > 0 {
				pidsChan <- pidsInfo{processName, pids}
			}
			time.Sleep(1 * time.Second)
		}
	}
}

// addPIDToCgroup добавляет PID в cgroup
func (PC *ProxyClient) addPIDToCgroup(pidsChan chan pidsInfo) {
	filePath := fmt.Sprintf("%s/cgroup.procs", cgroupPath)
	f, err := os.OpenFile(filePath, os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		PC.Logger.Printf("[-] Failed to open cgroup at %s: %v\n", filePath, err)
	}
	defer f.Close()

	cache := make(map[string]struct{})
	var mu sync.Mutex
	for {
		select {
		case <-PC.Ctx.Done():
			return
		case info := <-pidsChan:
			for _, pid := range info.pids {
				mu.Lock()
				if _, exists := cache[pid]; !exists {
					err := PC.writePIDToCgroup(pid)
					if err != nil {
						PC.Logger.Printf("[-] Failed to write PID %s: %v\n", pid, err)
					} else {
						cache[pid] = struct{}{}
						PC.Logger.Printf("[+] Added process %s with PID %s to cgroup\n", info.processName, pid)
					}
				}
				mu.Unlock()
			}
		}
	}
}

// writePIDToCgroup записывает один PID в cgroup
func (PC *ProxyClient) writePIDToCgroup(pid string) error {
	filePath := fmt.Sprintf("%s/cgroup.procs", cgroupPath)
	f, err := os.OpenFile(filePath, os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(pid + "\n")
	return err
}

// disableRules отключает созданные правила iptables
func (PC *ProxyClient) disableRules() error {
	// TCP правила
	tcpRules := []string{
		fmt.Sprintf("-t nat -D OUTPUT -m cgroup --path %s -p tcp ! -d %s --dport 80 -j DNAT --to-destination %s:%s", cgroupName, proxyIP, proxyIP, proxyPort),
		fmt.Sprintf("-t nat -D OUTPUT -m cgroup --path %s -p tcp ! -d %s --dport 443 -j DNAT --to-destination %s:%s", cgroupName, proxyIP, proxyIP, proxyPort),
	}

	// UDP правила
	udpRules := []string{
		fmt.Sprintf("-t nat -D OUTPUT -m cgroup --path %s -p udp ! -d %s --dport 53 -j DNAT --to-destination %s:%s", cgroupName, proxyIP, proxyIP, proxyPort),
	}

	for _, rule := range append(tcpRules, udpRules...) {
		cmd := exec.Command("iptables", strings.Split(rule, " ")...)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("rule '%s' failed: %v\n%s", rule, err, output)
		}
	}
	return nil
}

// applyIptablesRules создает правила iptables
func (PC *ProxyClient) applyIptablesRules() error {
	// TCP правила
	tcpRules := []string{
		fmt.Sprintf("-t nat -A OUTPUT -m cgroup --path %s -p tcp ! -d %s --dport 80 -j DNAT --to-destination %s:%s", cgroupName, proxyIP, proxyIP, proxyPort),
		fmt.Sprintf("-t nat -A OUTPUT -m cgroup --path %s -p tcp ! -d %s --dport 443 -j DNAT --to-destination %s:%s", cgroupName, proxyIP, proxyIP, proxyPort),
	}

	// UDP правила
	udpRules := []string{
		fmt.Sprintf("-t nat -A OUTPUT -m cgroup --path %s -p udp ! -d %s --dport 53 -j DNAT --to-destination %s:%s", cgroupName, proxyIP, proxyIP, proxyPort),
	}

	for _, rule := range append(tcpRules, udpRules...) {
		cmd := exec.Command("iptables", strings.Split(rule, " ")...)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("rule '%s' failed: %v\n%s", rule, err, output)
		}
	}
	return nil
}
