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

//void dealPacket(char* buf, int length);
//void reply(uint8_t* recvBuf,int recvLength);
void repack(uint8_t* recvBuf,int recvLength);
void unpack(uint8_t* recvBuf,int recvLength);

char* printIP(uint32_t ip);
uint32_t getNetAddr(uint32_t ip, uint32_t netmaskNum);
void  printRouteTable();
void  printDeviceTable();
uint16_t checkSum(unsigned char *addr, int length);

int main(int argc, char* argv[]){
   // readHostIP();     //get host ip addr from configure.file
    
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
//    printf("vpnentrance %s %x\n",printIP(vpnEntrance),vpnEntrance);assert(0);
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
        //printf("%d %d\n",addr.sll_pkttype,PACKET_HOST);
        //printf("%d %d\n",addr.sll_hatype,ARPHRD_ETHER);
        
        //if(addr.sll_pkttype == PACKET_HOST){
        if((addr.sll_hatype == ARPHRD_ETHER)){
            struct EthPack* ethPack = (struct EthPack*)recvBuf;
            struct IPPack* ipPack = (struct IPPack*) &ethPack->ipPack;
            //printf(" 0x%08x 0x%08x\n",ipPack->dstIP,eth0IP);
            if(ipPack->dstIP == vpnEntrance ){
                printf("Receiving a packet from another VPNServer\n");
                //reply(recvBuf,recvLength);
                unpack(tmpBuf,recvLength);
            }
            else if(getNetAddr(ipPack->srcIP,24)==getNetAddr(eth0IP,24)){
                printf("repacking\n");
                printf("\nvpnentrace110:%x\n",vpnEntrance);
                repack(tmpBuf,recvLength);
                //dealPacket(recvBuf,BUFSIZE);
            }
        }
       // struct EthPack* ipPack = (struct IPPack*)recvBuf;
        /*if(addr.sll_pkttype == PACKET_HOST){
            struct sockaddr_ll dest_addr = {
                .sll_family   = AF_PACKET,
                .sll_protocol = htons(ETH_P_IP),
                .sll_halen    = ETH_ALEN,
                .sll_ifindex  = ifIndex,
            };

            uint32_t temp = ipPack->srcIP;
            ipPack->srcIP = ipPack->dstIP;
            ipPack->dstIP = temp;
            ipPack->checksum = checkSum(ipPack,IP_HEADER_LEN);

            char nextMac[ETH_ALEN]={0x00,0x0c,0x29,0xed,0xcb,0x9f};
            //getNextMac(nextMac);
            memcpy(&dest_addr.sll_addr, nextMac, ETH_ALEN);
            int ret = sendto(sockfd,  buf,       sizeof(struct IPPack), 
                     0,       (struct sockaddr *)&dest_addr, sizeof(dest_addr));
            if(ret < 0){
                perror("Error: Send ping failed!\n");
                assert(0);
            }
        }*/
       // memcpy(tmpBuf,recvBuf,BUFSIZE);
      
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
            //eth0IP = atoi(ip);
        }
        else if(ethx[4]=='8'){
            if (inet_pton(AF_INET, ip, (uint8_t*)&eth1IP) == -1){
                printf("Error: Reading ens38 ip failed!\n");
                assert(0);
            }
            printf("*** Get router1 ens38 IP : %s ***\n", ip);
            //eth1IP = atoi(ip);
        }
        else{ //gateway
            if (inet_pton(AF_INET, ip, (uint8_t*)&gwIP) == -1){
                printf("Error: Reading host gwIP failed!\n");
                assert(0);
            }
            printf("*** Get router1 default gateway IP: %s ***\n\n", ip);
           // gwIP = atoi(ip);
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
    strcpy(req.ifr_name, ifName);//, IFNAMSIZ - 1);
   // printf("*** ifName : %s ***\n",ifName);

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

   /*
    printf("*** Get %s MacAddr: ",ifName); 
    int i = 0;
    for (; i < 5; i++){
        printf("%02x:", *(uint8_t*)(macAddr+i));
    }
    printf("%02x ***\n\n", macAddr[i]);*/

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
    //if ((sfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) < 0){
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
            //inet_ntoa(((struct sockaddr_in*)&req.ifr_addr)->sin_addr)); 
    close(sfd);
}

void getIfIndex(const char* ifName, uint32_t* ifIndex){
    struct ifreq req;
    memset(&req, 0, sizeof(struct ifreq));

    if(strlen(ifName) > IFNAMSIZ-1){
        perror("Error: getIfInfo, strlen(ifName) too large\n");
        assert(0);
    }
    strcpy(req.ifr_name, ifName);//, IFNAMSIZ - 1);
   // printf("*** ifName : %s ***\n",ifName);

    //AF_PACKET: Low level packet interface
    int sfd = 0;
    if ((sfd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))) < 0){
        perror("Error: getIfInfo(), sfd");
        assert(0);
    }     
    // get interface index 
    // SIOCGIFINDEX :Retrieve the interface index of the interface into ifr_ifindex.
    if (ioctl(sfd, SIOCGIFINDEX, &req) < 0){
        perror("Error: Get ifindex failed");
        assert(0);
    }
    *ifIndex = req.ifr_ifindex;
  //  printf("    ifIndex = %d\n", *ifIndex);
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
    FILE* fp = fopen("vpn_server1.txt","r+");
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
        //printf("net:%s  gw:%s  ifname:%s\n",net,gateway,ifname);
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
        /*
        routeTable[routeItemNum].
        //if(strcmp(ifname,ifName0)==0){
            //strcpy(routeTable[routeItemNum].ifIndex,ifName0);
        
        //}
        //else if(strcmp(ifname,ifName1)==0){
            //strcpy(routeTable[routeItemNum].ifIndex,ifName1);
        //    routeTable[routeItemNum].ifIndex = 3;
        //}
        printf("*** Route Rule %d:%s/%d via %s *** \n",
                routeItemNum,       net,
                routeTable[routeItemNum].netmask,
                ifname);*/
        
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

void reply(uint8_t* recvBuf, int recvLength){
    struct EthPack* ethPack = (struct EthPack*)recvBuf;
    //printf("Dealing\n");
    //printf("%04x %04x\n",ethPack->ethType,PROTO_IP);
    if(ethPack->ethType == htons(ETH_P_ARP)){
        printf("Receiving an ARP packet!\n");
    }
    else if(ethPack->ethType == htons(PROTO_IP)){
        struct IPPack* ipPack =(struct IPPack*) &ethPack->ipPack;
        struct IcmpPack* icmpPack = (struct IcmpPack*)(ipPack->payload);
        /*printf("ippack[0]=%02x ippack[20]=%02x icmp[0]=%02x \n",
                *((uint8_t*)ipPack),
                *((uint8_t*)ipPack+20),
                *((uint8_t*)icmpPack));
        printf("%04x %04x\n",ipPack->protocol,IP_ICMP);*/
        if(ipPack->protocol!=IP_ICMP){
            printf("Not a ICMP Packet\n");
            printf("icmpPack->type:%02x",icmpPack->type);
            printf("  %d \n\n",(uint8_t*)&icmpPack->type-(uint8_t*)ipPack);
            return;
        }
        uint32_t ipHdrLen = ipPack->header_length * 4;
       
        //printf("icmpPack->type:%02x",icmpPack->type);
        //printf("  %d \n",(uint8_t*)&icmpPack->type-(uint8_t*)ipPack);
        switch(icmpPack->type){
            case ICMP_ECHO_REQUEST:{
                uint32_t tmp = ipPack->srcIP;
                ipPack->srcIP = ipPack-> dstIP;
                ipPack->dstIP = tmp;

                icmpPack->type = ICMP_ECHO_REPLY;
                icmpPack->checksum = 0;
                icmpPack->checksum = checkSum((uint8_t*)icmpPack,sizeof(struct IcmpPack));
                struct sockaddr_ll dstAddr = {
                    .sll_family = AF_PACKET,
                    .sll_protocol = htons(ETH_P_IP),
                    .sll_halen = ETH_ALEN,
                    .sll_ifindex = ifIndex,
                };
                char nextMac[ETH_ALEN]={0x00,0x0c,0x29,0x26,0x3e,0x85};//pc1
                memcpy(&dstAddr.sll_addr,nextMac,ETH_ALEN);
                //sockfd = socket(AF_INET,SOCK_RAW,htons(ETH_P_ALL));
                sendto(sockfd, recvBuf, recvLength,
                    0, (struct sockaddr*)&dstAddr,sizeof(struct sockaddr_ll));
                printf("Reply ICMP successfully: from %s ",printIP(ipPack->srcIP));
                printf("to %s\n",printIP(ipPack->dstIP));
                //close(sockfd);
            }break;
            case ICMP_UNREACHABLE:
                printf("Destination unreachable!\n\n");
                break;
        }
    }
}

void dealPacket(char* buf, int length){
    struct EthPack* ethPack = (struct EthPack*)buf;
   
    //printf("%04x %04x \n",ethPack->ethType,PROTO_IP);
    if(ethPack->ethType == htons(ETH_P_ARP)){
        printf("Receiving Arp Packet, but I cant handle it.\n");
        assert(0);
    }
    else if(ethPack->ethType == htons(PROTO_IP)){
        struct IPPack* ipPack = (struct IPPack*)&(ethPack->ipPack);
        // printf("%d ",((uint8_t*)&ethPack->ethType)-(uint8_t*)ethPack);
        // printf("%d \n",((uint8_t*)&(ethPack->ipPack))-(uint8_t*)ethPack);
        //printf("%d ",((uint8_t*)ipPack)-(uint8_t*)ethPack);
        //printf("%02x %02x\n",*((uint8_t*)ethPack+14),
        //               *((uint8_t*)ipPack));
        //printf("pro %x\n",ipPack->protocol);
        switch(ipPack->protocol){
            case IP_ICMP: printf("Receving a ICMP Packet \n");break;
            default : printf("Receiving an unknown packet!\n");
        }
        printf("%s ---> ",printIP(ipPack->srcIP));//otherwise not flush the buffer
        printf("%s",printIP(ipPack->dstIP));
        //printf("%d\n",routeItemNum);
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
                break;
            }
        }
        if(i == routeItemNum){
            printf("Unluckily : No Routing Rule!\n");
        }
        else{
            struct sockaddr_ll dstAddr = {
                .sll_family =AF_PACKET,
                .sll_protocol = htons(ETH_P_IP),
                .sll_halen = ETH_ALEN,
                .sll_ifindex = routeTable[i].ifIndex,
            };
            //Use NetAddr to get ifIndex from RouteTable
            //Then use ifIndex to get mac
           /* int j=0;
            for(;j<deviceItemNum;j++){
                if(deviceTable[j].ifIndex == routeTable[i].ifIndex){
                    memcpy(dstAddr.sll_halen,deviceTable[j].macAddr,ETH_ALEN);
                    printf("%s %s\n",routeTable[i].ifIndex,
                                     deviceTable[j].macAddr);
                }
            }*/
            if( routeTable[i].ifIndex == 2){
                char tmp[6]={0x00,0x0c,0x29,0x26,0x3e,0x85};// pc1
                memcpy(dstAddr.sll_addr,tmp,ETH_ALEN);
            }
            else if( routeTable[i].ifIndex  == 3 ){
                char tmp[6]={0x00,0x0c,0x29,0x45,0x09,0x25};//router2 ens38 mac
                memcpy(dstAddr.sll_addr,tmp,ETH_ALEN);
            }
            int ret = sendto(sockfd, buf, length,
                        0,(struct sockaddr*)&dstAddr,sizeof( struct sockaddr_ll));
            if(ret < 0){
                printf("Send Failed!\n");
                assert(0);
            }
            printf("Send successfully!\n");
        }


    
    
    }
}

void repack(uint8_t* recvBuf,int recvLength){
    printf("\nvpnentrace111:%x\n",vpnEntrance);
    struct EthPack* ethPack = (struct EthPack*)recvBuf;
    
    //printf("%04x %04x \n",ethPack->ethType,PROTO_IP);
    if(ethPack->ethType == htons(ETH_P_ARP)){
        printf("Receiving Arp Packet, but I cant handle it.\n");
      //  assert(0);
    }
    else if(ethPack->ethType == htons(PROTO_IP)){
        struct IPPack* ipPack = (struct IPPack*)&(ethPack->ipPack);
        switch(ipPack->protocol){
            case IP_ICMP: printf("Receving a ICMP Packet \n");break;
            default : printf("Receiving an unknown packet!\n");
        }
        printf("%s ---> ",printIP(ipPack->srcIP));//otherwise not flush the buffer
        printf("%s",printIP(ipPack->dstIP));
        //printf("%d\n",routeItemNum);

        //ipPack->total_length -= htons(IP_HEADER_LEN);
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
        
           /* if( routeTable[i].ifIndex == 2){
                char tmp[6]={0x00,0x0c,0x29,0x26,0x3e,0x85};// pc1
                memcpy(dstAddr.sll_addr,tmp,ETH_ALEN);
            }
            else*/
            //printf("\nrouteTable[i].ifIndex=%d\n",routeTable[i].ifIndex);
             if( routeTable[i].ifIndex  == 3 ){
                // assert(0);
                char tmp[6]={0x00,0x0c,0x29,0x18,0xaf,0xe5};//network
                memcpy(dstAddr.sll_addr,tmp,ETH_ALEN);
                memcpy(newethPack.dstMacAddr,tmp,ETH_ALEN);
                getIfMac(ifName1,newethPack.srcMacAddr);
                
            
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
    if(ethPack->ethType == htons(ETH_P_ARP)){
        printf("Receiving Arp Packet, but I cant handle it.\n");
    }
    else if(ethPack->ethType == htons(PROTO_IP)){
        char ipTmp[100];
        struct IPPack* ipPack = (struct IPPack*)&(ethPack->ipPack);
        memcpy(ipTmp             ,ipPack->payload,84);
        memset(&(ethPack->ipPack),0              ,500);
        memcpy(&(ethPack->ipPack),ipTmp          ,84);

        struct IcmpPack* icmpPack = (struct IcmpPack*)&(ipPack->payload);
        icmpPack->checksum = 0;
        icmpPack->checksum = checkSum((uint8_t*)icmpPack,64);
   
        int i=0;
        for(;i<routeItemNum;i++){
            uint32_t netAddr = getNetAddr(ipPack->dstIP,
                                         routeTable[i].netmask);
            printf("%s\n",printIP(netAddr));
            if(netAddr == routeTable[i].dstNet){
                printf("(%s/%d) via interface %d\n",
                        printIP(routeTable[i].dstNet),
                        routeTable[i].netmask,
                        routeTable[i].ifIndex);
                break;
            }
        }

        if(i == routeItemNum){
            printf("Unluckily : No Routing Rule!\n");
        }
        else{
            struct sockaddr_ll dstAddr = {
                .sll_family = AF_PACKET,
                .sll_family = htons(ETH_P_IP),
                .sll_halen = ETH_ALEN,
                .sll_ifindex = routeTable[i].ifIndex,
            };

            if(routeTable[i].ifIndex == 2){
                char tmp[6]={0x00,0x0c,0x29,0x26,0x3e,0x85};//pc1 macAddr
                memcpy(dstAddr.sll_addr,tmp,ETH_ALEN);
                memcpy(ethPack->dstMacAddr,tmp,ETH_ALEN);
                getIfMac(ifName0,ethPack->srcMacAddr);
            }
            int ret = sendto(sockfd,(void*)ethPack,
                        recvLength-IP_HEADER_LEN,
                        0, (struct sockaddr*)&dstAddr,
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

uint16_t checkSum(unsigned char *addr, int length)
{
    unsigned short *p = (unsigned short *)addr;
    unsigned int sum = 0;
    while (length > 1)
    {
        sum += *p;
        p++;
        length = length - 2;
    }
    if (length == 1)
    {
        sum += *p;
    }

    while ((sum >> 16) != 0)
    {
        sum = (sum >> 16) + (sum & 0xffff);
    }
    return (unsigned short)(~sum);
}