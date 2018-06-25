service network-manager stop
ifconfig ens33 10.0.0.1 netmask 255.255.255.0
ifconfig ens38 192.168.0.2 netmask 255.255.255.0
route add default gw 192.168.0.1
sudo /etc/init.d/networking restart
