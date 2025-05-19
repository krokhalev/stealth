package main

import (
	"context"
	"fmt"
	"github.com/sirupsen/logrus"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
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
func Init(ctx context.Context, wg *sync.WaitGroup, initDone chan struct{}, logger *logrus.Logger, errChan chan error) {
	wg.Add(1)
	defer Cleanup(wg, logger)

	// 1. Создаем cgroup
	err := createCgroup()
	if err != nil {
		errChan <- fmt.Errorf("failed to create cgroup: %v", err)
		return
	}
	logger.Infof("[+] Created cgroup: %s\n", cgroupPath)

	// 2. Создаем iptables
	err = applyIptablesRules()
	if err != nil {
		errChan <- fmt.Errorf("failed to apply iptables rule: %v", err)
		return
	}
	logger.Info("[+] Applied iptables rules")

	initDone <- struct{}{}

	// 3. Находим PIDs по имени процесса
	// Если процесс создает новый подпроцесс, так же находим его и передаем в cgroup
	processNames := []string{"discord", "brave"}
	pidsChan := make(chan pidsInfo, len(processNames))
	for _, name := range processNames {
		go findPIDs(ctx, name, pidsChan)
	}

	// 4. Добавляем PIDs в cgroup
	go addPIDToCgroup(ctx, pidsChan, logger)

	// 5. Ожидаем завершения
	<-ctx.Done()
	logger.Info("[!] Caught termination signal")
}

// Cleanup чистит crgoup и iptables
func Cleanup(wg *sync.WaitGroup, logger *logrus.Logger) {
	// 0. Чистим cgroup и iptables
	// todo: придумать нормальный путь для удаления сигруппы
	//if err := os.RemoveAll(cgroupPath); err != nil {
	//	log.Printf("[-] Failed to remove cgroup dir: %v", err)
	//} else {
	//	fmt.Println("[+] Removed cgroup directory")
	//}
	if err := disableRules(); err != nil {
		logger.Errorf("[-] Failed to disable iptables: %v", err)
	} else {
		logger.Info("[+] Disabled iptables")
	}
	wg.Done()
}

// createCgroup создает директорию cgroup
func createCgroup() error {
	err := os.MkdirAll(cgroupPath, 0755)
	if err != nil && !os.IsExist(err) {
		return err
	}
	return nil
}

// getCgroupInode вернет inode группы
func getCgroupInode() (string, error) {
	var stat syscall.Stat_t
	err := syscall.Stat(cgroupPath, &stat)
	if err != nil {
		return "", fmt.Errorf("[-] Failed to stat cgroup path: %w", err)
	}
	return fmt.Sprintf("%d", stat.Ino), nil
}

// findPIDs ищет PIDs процесса по имени
func findPIDs(ctx context.Context, processName string, pidsChan chan pidsInfo) {
	for {
		select {
		case <-ctx.Done():
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
func addPIDToCgroup(ctx context.Context, pidsChan chan pidsInfo, logger *logrus.Logger) {
	filePath := fmt.Sprintf("%s/cgroup.procs", cgroupPath)
	f, err := os.OpenFile(filePath, os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		logger.Printf("[-] Failed to open cgroup at %s: %v\n", filePath, err)
	}
	defer f.Close()

	cache := make(map[string]struct{})
	var mu sync.Mutex
	for {
		select {
		case <-ctx.Done():
			return
		case info := <-pidsChan:
			for _, pid := range info.pids {
				mu.Lock()
				if _, exists := cache[pid]; !exists {
					err := writePIDToCgroup(pid)
					if err != nil {
						logger.Printf("[-] Failed to write PID %s: %v\n", pid, err)
					} else {
						cache[pid] = struct{}{}
						logger.Printf("[+] Added process %s with PID %s to cgroup\n", info.processName, pid)
					}
				}
				mu.Unlock()
			}
		}
	}
}

// writePIDToCgroup записывает один PID в cgroup
func writePIDToCgroup(pid string) error {
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
func disableRules() error {
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
func applyIptablesRules() error {
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
