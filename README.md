[Локальное приложение]  
↓  
iptables REDIRECT  
↓  
[Локальный прокси на 127.0.0.1:12345]  
↓  
[Удаленный сервер-прокси]  
↓  
[Целевой сервер (discord.com / youtube.com)]  
↓  
[Ответ обратно по цепочке]  

sudo env "PATH=$PATH" go run unix/init.go
watch -n 1 'cat /sys/fs/cgroup/myproxygroup/cgroup.procs'
sudo conntrack -L -o extended | grep -E "127.0.0.1| (cat /sys/fs/cgroup/myproxygroup/cgroup.procs | tr '\n' '|')"

sudo iptables -t nat -D OUTPUT -m cgroup --path myproxygroup -p tcp ! -d 127.0.0.1 --dport 80 -j DNAT --to-destination 127.0.0.1:12345
sudo iptables -t nat -D OUTPUT -m cgroup --path myproxygroup -p tcp ! -d 127.0.0.1 --dport 443 -j DNAT --to-destination 127.0.0.1:12345
sudo iptables -t nat -D OUTPUT -m cgroup --path myproxygroup -p udp ! -d 127.0.0.1 --dport 53 -j DNAT --to-destination 127.0.0.1:12345
sudo iptables -t nat -L -n -v
