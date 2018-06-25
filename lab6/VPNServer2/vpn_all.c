#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <assert.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <arpa/inet.h>//inet_pton
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <netinet/in.h> //PROTO_IPIP = 4
#include <linux/if_packet.h>
#include <linux/if_ether.h>//ETH_P_IP=0x8000; ETH_ALEN=6
#include"type.h"

struct EthPack newethPack;
const char *ifName0 = "ens33";
const char *ifName1 = "ens38";
uint32_t dstIP;
uint32_t eth0IP;
uint32_t eth1IP;
uint32_t gwIP;
uint32_t sockfd;
uint32_t sockfdVPN;
uint32_t ifIndex;

uint32_t vpnEntrance=1;//ip address
char vpnExit[20]; //ens33 or ens38

struct RouteItem routeTable[MAX_ROUTE_NUM];
int routeItemNum = 0;
struct ArpTableItem arpTable[MAX_ARPITEM_NUM]; 
int arpItemNum = 0;
struct DeviceItem deviceTable[MAX_DEVICE_NUM]; // the sum of the interfacegot information from configuration file : if.info
int deviceItemNum = 0;

//void readHostIP();
void readRouteTable();
void getIfIndex(const char* ifName, uint32_t* ifIndex);
void getIfMac(const char*ifName, char* macAddr);
void getIfIP(const char*ifName, uint32_t* ip);

void repack(uint8_t* recvBuf,int recvLength);
void unpack(uint8_t* recvBuf,int recvLength);

char* printIP(uint32_t ip);
uint32_t getNetAddr(uint32_t ip, uint32_t netmaskNum);
void  printRouteTable();
void  printDeviceTable();
uint16_t checkSum(unsigned char *addr, int length);

int main(int argc, char* argv[]){
    getIfIndex(ifName0,  &deviceTable[0].ifIndex);//get host mac addr
    getIfMac(ifName0, deviceTable[0].macAddr);
    getIfIP(ifName0,&deviceTable[0].ipAddr);
    eth0IP = deviceTable[0].ipAddr;// = eth0IP;
    deviceItemNum++;

    getIfIndex(ifName1, &deviceTable[1].ifIndex);
    getIfMac(ifName1, deviceTable[1].macAddr);
    getIfIP(ifName1,&deviceTable[1].ipAddr);
    eth1IP = deviceTable[1].ipAddr;// = eth1IP;
    deviceItemNum++;

    readRouteTable();
    printRouteTable();
    printDeviceTable();

    if((sockfd = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL))) == -1){
        perror("Error:Socket initialize failed!\n");
        assert(0);
    }
    
    uint8_t recvBuf[BUFSIZE];
    while(1){
        uint8_t tmpBuf[BUFSIZE];
        struct sockaddr_ll addr;
        socklen_t addrLen = sizeof(struct sockaddr_ll);

        memset(recvBuf,0,BUFSIZE);
        uint32_t recvLength = recvfrom(sockfd,recvBuf,BUFSIZE,
                                        0,(struct sockaddr*)&addr,
                                        &addrLen);
        if(recvLength < 0){
            perror("Error: Receive packets failed!\n");
            assert(0);
        }
        memcpy(tmpBuf,recvBuf,recvLength);

        ifIndex = addr.sll_ifindex;
 
        if((addr.sll_hatype == ARPHRD_ETHER)){
            struct EthPack* ethPack = (struct EthPack*)recvBuf;
            struct IPPack* ipPack = (struct IPPack*) &ethPack->ipPack;

            if(ipPack->dstIP == vpnEntrance ){
                printf("Receiving a packet from another VPNServer\n");
                unpack(tmpBuf,recvLength);
            }
            else if(getNetAddr(ipPack->srcIP,24)==getNetAddr(eth1IP,24)
                    && ipPack->ttl == 64){
                printf("repacking\n");
                repack(tmpBuf,recvLength);
            }
        }
   }

}

void readHostIP(){
    char ethx[100];
    char ip[100];
    FILE *fp = fopen("ip_router1.txt", "r+");
    while(!feof(fp)){
        fscanf(fp,"%s %s\n",ethx,ip);
        if(ethx[4]=='3'){
            if(inet_pton(AF_INET, ip, (uint8_t*)&eth0IP) == -1){
                printf("Error: Reading ens33 ip failed!\n");
                assert(0);
            }
            printf("*** Get router1 ens33 IP : %s ***\n", ip);
        }
        else if(ethx[4]=='8'){
            if (inet_pton(AF_INET, ip, (uint8_t*)&eth1IP) == -1){
                printf("Error: Reading ens38 ip failed!\n");
                assert(0);
            }
            printf("*** Get router1 ens38 IP : %s ***\n", ip);
        }
        else{ //gateway
            if (inet_pton(AF_INET, ip, (uint8_t*)&gwIP) == -1){
                printf("Error: Reading host gwIP failed!\n");
                assert(0);
            }
            printf("*** Get router1 default gateway IP: %s ***\n\n", ip);
        }
    }
    fclose(fp);
}

void getIfMac(const char* ifName, char* macAddr){
    struct ifreq req;
    memset(&req, 0, sizeof(struct ifreq));

    if(strlen(ifName) > IFNAMSIZ-1){
        perror("Error: getIfInfo, strlen(ifName) too large\n");
        assert(0);
    }
    strcpy(req.ifr_name, ifName);

    //AF_PACKET: Low level packet interface
    int sfd = 0;
    if ((sfd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))) < 0){
        perror("Error: getIfMac(), sfd");
        assert(0);
    }     
   
    //  get mac addr
    if (ioctl(sfd, SIOCGIFHWADDR, &req) < 0){
        perror("Error:Get Mac Addr Failed!");
        assert(0);
    }
    memset(macAddr, 0 ,ETH_ALEN);
    memcpy(macAddr, &(req.ifr_hwaddr.sa_data), ETH_ALEN);
    close(sfd);
}

void getIfIP(const char*ifName, uint32_t* ip){
    struct ifreq req;
    memset(&req, 0, sizeof(struct ifreq));

    if(strlen(ifName) > IFNAMSIZ-1){
        perror("Error: getIfInfo, strlen(ifName) too large\n");
        assert(0);
    }
    strcpy(req.ifr_name, ifName);

    //AF_PACKET: Low level packet interface
    int sfd = 0;
    if ((sfd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))) < 0){
        perror("Error: getIfIP(), sfd");
        assert(0);
    }     
    //  get ip addr
   // req.ifr_addr.sa_family = AF_INET;
    if (ioctl(sfd, SIOCGIFADDR, &req) < 0){
        perror("Error:Get IP Addr Failed!");
        assert(0);
    }
    
    *ip = ((struct sockaddr_in*)&req.ifr_addr)->sin_addr.s_addr;
  
    printf("*** Get %s IPAddr: %s ***\n",ifName,printIP(*ip));
    close(sfd);
}

void getIfIndex(const char* ifName, uint32_t* ifIndex){
    struct ifreq req;
    memset(&req, 0, sizeof(struct ifreq));

    if(strlen(ifName) > IFNAMSIZ-1){
        perror("Error: getIfInfo, strlen(ifName) too large\n");
        assert(0);
    }
    strcpy(req.ifr_name, ifName);


    //AF_PACKET: Low level packet interface
    int sfd = 0;
    if ((sfd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))) < 0){
        perror("Error: getIfInfo(), sfd");
        assert(0);
    }     
    // get interface index 
    // SIOCGIFINDEX :Retrieve the interface index of the interface into ifr_ifindex.
    if (ioctl(sfd, SIOCGIFINDEX, &req) < 0){
        perror("Error: Get ifindex failed");
        assert(0);
    }
    *ifIndex = req.ifr_ifindex;

}

void printDeviceTable(){
    printf("\n-------------------- Device Table ------------------------\n");
    printf("No.    interface         ipAddr           macAddr   \n");
    int i=0;
    for(;i<deviceItemNum;i++){
        printf("%d         %d          %s   \t%02x:%02x:%02x:%02x:%02x:%02x\n",i,
                deviceTable[i].ifIndex,
                printIP(deviceTable[i].ipAddr),
                deviceTable[i].macAddr[0],deviceTable[i].macAddr[1],
                deviceTable[i].macAddr[2],deviceTable[i].macAddr[3],
                deviceTable[i].macAddr[4],deviceTable[i].macAddr[5]);
    }
    printf("----------------------------------------------------------\n");

}

void readRouteTable(){
    FILE* fp = fopen("vpn_server2.txt","r+");
    if(fp == NULL){
        perror("File open failed!\n");
        assert(0);
    }
    char net[20];
    char ifname[20];
    char gateway[20];
    char entrance[20];
    char exit[20];

    while(!feof(fp)){
        fscanf(fp,"%s %s",entrance,exit);
        //printf("entrance:%s  vpnExit:%s\n",entrance,exit);
        if(inet_pton(AF_INET, entrance,&vpnEntrance) == -1){
            printf("Error: Reading vpnEntrance failed!\n");
            assert(0);
        }
        printf("*** Get server1 vpnEntrance : %s ***\n",printIP(vpnEntrance));

        memcpy(vpnExit,exit,20);
        printf("*** Get server1 vpnExit     : %s    ***\n", vpnExit);

        while(fscanf(fp, "%s %s %s", net, gateway, ifname)!=EOF){
            int i=0;
            while(net[i]!='/'){
            i++;
        }
        net[i] = '\0';
        inet_pton(AF_INET,net,&routeTable[routeItemNum].dstNet);//presentative to network
        routeTable[routeItemNum].netmask = atoi(&net[i+1]);
        inet_pton(AF_INET,gateway,&routeTable[routeItemNum].gateway);
        
        getIfIndex(ifname,&routeTable[routeItemNum].ifIndex);
        routeItemNum++;
        }
        
    }
    fclose(fp);
}

void printRouteTable(){
    printf("\n--------------- VPN Server Route Table ------------------\n");
    printf("No.     dstNet        netmask      interface    gw(vpn dst)\n");
    int i=0;
    for(;i<routeItemNum;i++){
        printf("%d      %s     ",i,
                printIP(routeTable[i].dstNet));
        printf("%s      %d       ",
                printIP(htonl(0xffffffff << (32-routeTable[i].netmask))),
                routeTable[i].ifIndex);
        printf("%s\n",printIP(routeTable[i].gateway));
    }
    printf("---------------------------------------------------------\n");
}


void repack(uint8_t* recvBuf,int recvLength){
    struct EthPack* ethPack = (struct EthPack*)recvBuf;
    
    if(ethPack->ethType == htons(ETH_P_ARP)){
        printf("Receiving Arp Packet, but I cant handle it.\n");
    }
    else if(ethPack->ethType == htons(PROTO_IP)){
        struct IPPack* ipPack = (struct IPPack*)&(ethPack->ipPack);
        switch(ipPack->protocol){
            case IP_ICMP: printf("Receving a ICMP Packet \n");break;
            default : printf("Receiving an unknown packet!\n");
        }
        printf("%s ---> ",printIP(ipPack->srcIP));//otherwise not flush the buffer
        printf("%s",printIP(ipPack->dstIP));

        struct IcmpPack* icmpPack = (struct IcmpPack*)&(ipPack->payload);
        icmpPack->checksum = 0;
        icmpPack->checksum = checkSum((uint8_t*)icmpPack,64);

        newethPack.ethType = ethPack->ethType;
        struct IPPack* newipPack = (struct IPPack*)&(newethPack.ipPack);
        memcpy(newipPack,ipPack,IP_HEADER_LEN);
        memcpy(newipPack->payload, ipPack, 500);
       

        int i=0;
        for(;i<routeItemNum;i++){
            uint32_t netAddr = getNetAddr(ipPack->dstIP,
                                        routeTable[i].netmask);
            //printf("%s\n",printIP(netAddr));
            if(netAddr == routeTable[i].dstNet){
                //printf("%s\n",printIP(routeTable[i].dstNet));
                printf("(%s/%d) via  interface %d \n",
                        printIP(routeTable[i].dstNet),
                        routeTable[i].netmask,
                        routeTable[i].ifIndex);

                newipPack->total_length = ipPack->total_length+htons(IP_HEADER_LEN);
                newipPack->protocol = IP_IPIP;
                newipPack->srcIP = vpnEntrance;
                printf("\nvpnentrace:%x\n",vpnEntrance);
                newipPack->dstIP = routeTable[i].gateway;
                newipPack->checksum = 0;
                newipPack->checksum = checkSum((uint8_t*)newipPack,IP_HEADER_LEN);
                break;
            }
        }
        if(i == routeItemNum){
            printf("  Unluckily : No Routing Rule!\n");
        }
        else{
            struct sockaddr_ll dstAddr = {
                .sll_family =AF_INET,
                .sll_protocol = htons(ETH_P_IP),
                .sll_halen = ETH_ALEN,
                .sll_ifindex = routeTable[i].ifIndex,
            };

            if( routeTable[i].ifIndex  == 2 ){
                char tmp[6]={0x00,0x0c,0x29,0x18,0xaf,0xef};//network ens38
                memcpy(dstAddr.sll_addr,tmp,ETH_ALEN);
                memcpy(newethPack.dstMacAddr,tmp,ETH_ALEN);
                getIfMac(ifName0,newethPack.srcMacAddr);
                ethPack->ethType = PROTO_IP;
            
            }
            printf("\nrecvlen=%d\n",recvLength);
            int ret = sendto(sockfd, (void*)&newethPack, 
                            recvLength+IP_HEADER_LEN,
                            0,(struct sockaddr*)&dstAddr,sizeof(struct sockaddr_ll));
            if(ret < 0){
                printf("Send Failed!\n");
                assert(0);
            }
            printf("Send successfully!\n");
        }
    
    }

}

void unpack(uint8_t* recvBuf,int recvLength){
    struct EthPack* ethPack = (struct EthPack*)recvBuf;
    //printf("%04x %04x \n",ethPack->ethType,PROTO_IP);
    if(ethPack->ethType == htons(ETH_P_ARP)){
        printf("Receiving Arp Packet, but I cant handle it.\n");
    }
    else if(ethPack->ethType == htons(PROTO_IP)){
        char ipTmp[100];
        struct IPPack* ipPack = (struct IPPack*)&(ethPack->ipPack);
        for(int p=0;p<100;p++){
            printf("%02x ",*((uint8_t*)recvBuf+p));
            if(p!=0 && p%16==0)
                printf("\n");
        }

        int len = ntohs(ipPack->total_length)-IP_HEADER_LEN;
            printf("%d\n", len);
        
            memcpy(ipTmp,        ipPack->payload,84);
            memset(&(ethPack->ipPack),0,500);
            memcpy(&(ethPack->ipPack),ipTmp, 84);
            
            struct IcmpPack* icmpPack = (struct IcmpPack*)&(ipPack->payload);
            icmpPack->checksum = 0;
            icmpPack->checksum = checkSum((uint8_t*)icmpPack,64);

        int i=0;
        for(;i<routeItemNum;i++){
            uint32_t netAddr = getNetAddr(ipPack->dstIP,
                                        routeTable[i].netmask);
            if(netAddr == routeTable[i].dstNet){
                //printf("%s\n",printIP(routeTable[i].dstNet));
                printf("(%s/%d) via interface %d \n",
                        printIP(routeTable[i].dstNet),
                        routeTable[i].netmask,
                        routeTable[i].ifIndex);

                break;
            }
        }
        if(i == routeItemNum){
            printf("  Unluckily : No Routing Rule!\n");
        }
        else{
            struct sockaddr_ll dstAddr = {
                .sll_family =AF_PACKET,
                .sll_protocol = htons(ETH_P_IP),
                .sll_halen = ETH_ALEN,
                .sll_ifindex = routeTable[i].ifIndex,
            };
        
            if( routeTable[i].ifIndex  == 3 ){
                // assert(0);
                char tmp[6]={0x00,0x0c,0x29,0x97,0x48,0xe6};//pc2 macAddr
                memcpy(dstAddr.sll_addr,tmp,ETH_ALEN);
                memcpy(ethPack->dstMacAddr,tmp,ETH_ALEN);
                getIfMac(ifName1,ethPack->srcMacAddr);
            
            }
            printf("\nrecvlen=%d\nsecond:\n",recvLength);
            for(int p=0;p<100;p++){
                if(p!=0 && p%16==0)
                    printf("\n");
                printf("%02x ",*((uint8_t*)ethPack+p));
            }   
            int ret = sendto(sockfd, (void*)ethPack, 
                            recvLength-IP_HEADER_LEN,
                            0,(struct sockaddr*)&dstAddr,
                            sizeof(struct sockaddr_ll));

            if(ret < 0){
                printf("Send Failed!\n");
                assert(0);
            }
            printf("Send successfully!\n");
        }
    }
}

char* printIP(uint32_t ip){
    static char tmp[50];
    memset(tmp,0,50);
    inet_ntop(AF_INET, &ip, tmp, INET_ADDRSTRLEN);
    return tmp;
}

uint32_t getNetAddr(uint32_t ip, uint32_t netmaskNum){
    uint32_t netmask = 0xffffffff << (32-netmaskNum);
    return htonl( ntohl(ip) & netmask );
}

uint16_t checkSum(unsigned char *addr, int length){
    unsigned short *p = (unsigned short *)addr;
    unsigned int sum = 0;
    while (length > 1){
        sum += *p;
        p++;
        length = length - 2;
    }
    if (length == 1){
        sum += *p;
    }

    while ((sum >> 16) != 0){
        sum = (sum >> 16) + (sum & 0xffff);
    }
    return (unsigned short)(~sum);
}