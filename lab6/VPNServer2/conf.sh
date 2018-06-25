service network-manager stop
ifconfig ens33 192.168.1.2 netmask 255.255.255.0
ifconfig ens38 10.0.1.1 netmask 255.255.255.0
route add default gw 192.168.1.1
sudo /etc/init.d/networking restart