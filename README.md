tun - транспортный интерфейс для передачи пакетов  
mtu - размер передаваемого пакета (Maximum Transmission Unit)  

- sudo env "PATH=$PATH" go run client.go - запустить клиент от имени администратора
- ip link show - показать список всех интерфейсов  
- ip route show - показать список маршрутов  
- ip link show tun0 - показать статус интерфейса
- ip tuntap add dev tun0 mode tun - создать tun интерфейс
- ip addr add 10.0.0.1/24 dev tun0 - назначить ip для интерфейса
- ip link set dev tun0 up - поднять интерфейс
- ip route add default via 10.0.0.1 dev tun0 - назначить дефолтный роут через интерфейс
- ip route add 0.0.0.0/1 dev tun0 - направить запросы первой половины IP-адресов в интерфейс (от 0.0.0.0 до 127.255.255.255)
- ip route add 128.0.0.0/1 dev tun0 - направить запросы первой половины IP-адресов в интерфейс (от 128.0.0.0 до 255.255.255.255)
- sudo tcpdump -i tun0 - проверить выходящие пакеты 
- sudo tcpdump -i tun0 -vv (-vvv) - для подробного протокольного анализа