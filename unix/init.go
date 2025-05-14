package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	cgroupPath = "/sys/fs/cgroup/myproxygroup"
)

type pidsInfo struct {
	processName string
	pids        []string
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// 1. Создаем cgroup
	err := createCgroup()
	if err != nil {
		log.Fatalf("[-] Failed to create cgroup: %v", err)
	}
	fmt.Printf("[+] Created cgroup: %s\n", cgroupPath)

	// 2. Получаем cgroup inode
	cgroupID, err := getCgroupInode()
	if err != nil {
		log.Fatalf("[-] Failed to get cgroup ID: %v", err)
	}
	fmt.Printf("[+] Cgroup ID (inode): %s\n", cgroupID)

	err = applyNftTablesRule(cgroupID, 12345)
	if err != nil {
		log.Fatalf("[-] Failed to apply nftables rule: %v", err)
	}
	fmt.Println("[+] Applied nft tables rules")

	// 3. Находим PIDs по имени процесса
	// Если процесс создает новый подпроцесс, так же находим его и передаем в cgroup
	processNames := []string{"discord", "brave"}
	pidsChan := make(chan pidsInfo, len(processNames))

	for _, name := range processNames {
		go findPIDs(ctx, name, pidsChan)
	}

	// 3. Добавляем PIDs в cgroup
	go addPIDToCgroup(ctx, pidsChan)

	<-ctx.Done()
	fmt.Printf("[!] Shutting down gracefully\n")
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
func addPIDToCgroup(ctx context.Context, pidsChan chan pidsInfo) {
	filePath := fmt.Sprintf("%s/cgroup.procs", cgroupPath)
	f, err := os.OpenFile(filePath, os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Printf("[-] Failed to open cgroup at %s: %v\n", filePath, err)
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
						fmt.Printf("[-] Failed to write PID %s: %v\n", pid, err)
					} else {
						cache[pid] = struct{}{}
						fmt.Printf("[+] Added process %s with PID %s to cgroup\n", info.processName, pid)
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

// applyNftTablesRule создает nft тейбл, привязывает cgroup и перенаправляет трафик в прокси клиент (127.0.0.1)
func applyNftTablesRule(cgroupID string, proxyPort int) error {
	rules := []string{
		"add table inet myproxy",
		"add chain inet myproxy prerouting { type nat hook prerouting priority 0 ; }",
		"add chain inet myproxy output { type route hook output priority -100 ; }",
		fmt.Sprintf("add rule inet myproxy output socket cgroupv2 level 0 %s dnat to 127.0.0.1:%d", cgroupID, proxyPort),
	}

	for _, rule := range rules {
		cmd := exec.Command("nft", strings.Split(rule, " ")...)
		output, err := cmd.CombinedOutput()
		if err != nil && !strings.Contains(string(output), "File exists") {
			return fmt.Errorf("[-] Failed to apply rule '%s': %v\n%s", rule, err, output)
		}
	}
	return nil
}
