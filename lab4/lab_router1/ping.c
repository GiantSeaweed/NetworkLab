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
#include <linux/if_packet.h>
#include <linux/if_ether.h>//ETH_P_IP=0x8000; ETH_ALEN=6
#include"type.h"

#define IP_ID 123
// the sum of the items in the arp cache int arp_item_index =0;
struct ArpTableItem arpTable[MAX_ARPITEM_NUM]; 
int arpItemNum = 0;

uint32_t dstIP;
uint32_t eth0IP;
uint32_t eth1IP;
uint32_t gwIP;
uint8_t hostMacAddr[6];
uint32_t ifIndex ;
uint32_t sockfd;
uint32_t icmpTransmitted = 0;
uint32_t icmpReceived = 0;
const char *ifName = "ens33";

void parseCmd(int argc, char* argv[]);
void readHostIP();
void getIfInfo(const char* ifName);
void sendPing(int sequence);
void recvPing();
void getNextMac(char* mac);
char* printIP(uint32_t ip) ;
uint16_t checkSum(unsigned char *addr, int length);

int main(int argc, char* argv[]){
    parseCmd(argc,argv);
    readHostIP();     //get host ip addr from configure.file
    getIfInfo(ifName);//get host mac addr
    if( (sockfd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL))) < 0){
        perror("Error:Init Socket Failed!\n");
        assert(0);
    }
    int sequence = 1;
    while(1){
        sendPing(sequence);
        recvPing();
        sleep(1);
    }
    return 0;
}

void parseCmd(int argc,char* argv[]){
    if(argc > 2){
        printf("Argc > 1\n");
        exit(0);
    }
    dstIP = atoi(argv[argc-1]);
}

void readHostIP(){
    char ethx[100];
    char ip[100];
    FILE *fp = fopen("ip_pc1.txt", "r+");
    while(!feof(fp)){
        fscanf(fp,"%s %s\n",ethx,ip);
        if(ethx[3]=='0'){
            if(inet_pton(AF_INET, ip, (uint8_t*)&eth0IP) == -1){
                printf("Error: Reading eth0 ip failed!\n");
                exit(0);
            }
            printf("*** Get eth0 IP   : %s ***\n", ip);
            //eth0IP = atoi(ip);
        }
        else if(ethx[3]=='1'){
            if (inet_pton(AF_INET, ip, (uint8_t*)&eth1IP) == -1)
            {
                printf("Error: Reading eth1 ip failed!\n");
                exit(0);
            }
            printf("*** Get eth1 IP: %s ***\n", ip);
        }
        else{
            if (inet_pton(AF_INET, ip, (uint8_t*)&gwIP) == -1)
            {
                printf("Error: Reading host gwIP failed!\n");
                exit(0);
            }
            printf("*** Get Gateway IP: %s ***\n", ip);
        }
    }
    fclose(fp);
}

void getIfInfo(const char *ifName)
{
    struct ifreq req;
    memset(&req, 0, sizeof(req));

    if(strlen(ifName) > IFNAMSIZ-1){
        perror("Error: getIfInfo, strlen(ifName) too large\n");
        assert(0);
    }
    strcpy(req.ifr_name, ifName);
    printf("*** ifName : %s ***\n",ifName);

    //AF_PACKET: Low level packet interface
    int sfd = 0;
    if ((sfd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))) < 0)
    {
        perror("Error: getIfInfo(), sfd\n");
        assert(0);
    }     

    // get interface index 
    // SIOCGIFINDEX :Retrieve the interface index of the interface into ifr_ifindex.
    if (ioctl(sfd, SIOCGIFINDEX, &req) < 0)
    {
        perror("Error: Get ifindex failed\n");
        assert(0);
    }
    ifIndex = req.ifr_ifindex;

    //  get mac addr
    if (ioctl(sfd, SIOCGIFHWADDR, &req) < 0)
    {
        perror("Error:Get Mac Addr Failed!\n");
        assert(0);
    }
    memcpy(&hostMacAddr[0], &(req.ifr_hwaddr.sa_data), ETH_ALEN);
    printf("*** Get host MacAddr: "); //, hostMacAddr+'0');
    int i = 0;
    for (; i < 5; i++){
        printf("%02x:", hostMacAddr[i]);
    }
    printf("%02x ***\n", hostMacAddr[i]);

    close(sfd);
}

void getNextMac(char* dstMac){
    //search in the arpTable
    int i = 0 ;
    for(;i < arpItemNum; i++){
        if(dstIP == arpTable[i].ipAddr){
            memcpy(dstMac,arpTable[i].macAddr,ETH_ALEN);
            return ;
        }
    }

    //if search failed, then send arp packet
    uint8_t arpBuf[sizeof(struct EthArpPack)];
    struct EthArpPack *arpPack = (struct EthArpPack*)arpBuf;
    memset(arpPack->dstMacAddr, 0xff, ETH_ALEN); //Broadcast
    memcpy(arpPack->srcMacAddr, hostMacAddr, ETH_ALEN);
    memset(&arpPack->ethType, PROTO_ARP, 2);

    arpPack->hrdType = htons(HW_TYPE); //ethernet:1
    arpPack->proType = htons(PROTO_IP);
    arpPack->hrdLen = ETH_ALEN;
    arpPack->proLen = IP_ALEN;
    arpPack->opcode = htons(ARP_REQUEST);
    memcpy(arpPack->srcHrdAddr, hostMacAddr, ETH_ALEN);
    arpPack->srcProAddr = htons(eth0IP);
    memset(arpPack->dstHrdAddr, 0, ETH_ALEN);
    arpPack->dstProAddr = htons(dstIP);

    struct sockaddr_ll destAddr = {
        .sll_family  = AF_PACKET,
        .sll_protocol= htons(ETH_P_IP),
        .sll_halen   = ETH_ALEN,
        .sll_ifindex = ifIndex,
    };
    //memcpy(&destAddr.sll_addr, &dest_mac_addr, ETH_ALEN);
    sendto(sockfd,                        arpBuf, sizeof(struct EthArpPack), 
                0,  (struct sockaddr *)&destAddr, sizeof(destAddr)  );
    
    while(1){
        uint8_t tmp[BUFSIZ];
        int sfd = recvfrom(sockfd, tmp, BUFSIZ, 0, 0, NULL);
        if(sfd < 0){
            perror("Error:Receive Arp Reply Failed!\n");
            assert(0);
        }
        struct EthArpPack *recvArp = (struct EthArpPack*) tmp;
        if (ntohs(recvArp->ethType) != PROTO_ARP)
        {
            printf("Not an Arp Packet!\n");
            continue;
        }
        if (ntohs(recvArp->opcode) != ARP_REPLY)
        {
            printf("Not Arp Reply!\n");
            continue;
        }

        struct in_addr addTemp = {
            .s_addr = recvArp->srcProAddr,
        };
        printf("Arp Packet : Reply from %s\n", inet_ntoa(addTemp));
        printf("MAC Address is : %02x:%02x:%02x:%02x:%02x:%02x \n",
               recvArp->srcHrdAddr[0], recvArp->srcHrdAddr[1], recvArp->srcHrdAddr[2],
               recvArp->srcHrdAddr[3], recvArp->srcHrdAddr[4], recvArp->srcHrdAddr[5]);
        
        memcpy(dstMac, recvArp->srcHrdAddr, ETH_ALEN);
        //update the arpTable
        int i = 0;
        for(;i<arpItemNum;i++){
            if (arpTable[i].ipAddr == recvArp->srcProAddr)
            {
                break;
            }
        }
        if(i == arpItemNum){
            arpTable[i].ipAddr = recvArp->srcProAddr;
            memcpy(arpTable[i].macAddr, recvArp->srcHrdAddr, ETH_ALEN);
            arpItemNum++;
        }
    }
}

void sendPing(int sequence)
{
    /* sin_family refers to Address Protocol Family
     * It can only be AF_INET in Socket Programming
     */
    /* inet_addr():IP Address(NUMS-AND-DOTS)  ==> Binary Data in Network Order
     * inet_ntoa():Data in Network Order      ==> IP Address(NUMS_AND_DOTS)
     */

    //IP header
    uint8_t buf[sizeof(struct IPPack)];
   
    struct IPPack *ipPack = (struct IPPack *)buf;
    memset(ipPack, 0, sizeof(struct IPPack));
    ipPack->header_length = 5;
    ipPack->version = 4;
    ipPack->id = htons(IP_ID);
    ipPack->ttl = 64 ;
    ipPack->protocol = IP_ICMP;
    ipPack->checksum = 0;
    ipPack->srcIP = eth0IP;
    ipPack->dstIP = dstIP;
    ipPack->checksum = checkSum((uint8_t*)ipPack,20);//ip header 20

    //ICMP header
    struct IcmpPack *icmpPack = (struct IcmpPack*)(ipPack->payload);
    memset(icmpPack, 0, sizeof(struct IcmpPack));
    icmpPack->type = ICMP_ECHO_REQUEST ; //ICMP_ECHO_REPLY=0(Reply); ICMP_ECHO_REQUEST=8(Request)
    icmpPack->code = 0;
    icmpPack->checksum = 0; //clear the checkSum field*/
    icmpPack->id = htons(getpid());
    icmpPack->sequence = htons(sequence);
    gettimeofday((struct timeval*)icmpPack->data, NULL);
    icmpPack->checksum = checkSum((uint8_t *)icmpPack, sizeof(struct IcmpPack)); //icmp length:

    struct sockaddr_ll dest_addr = {
        .sll_family   = AF_PACKET,
        .sll_protocol = htons(ETH_P_IP),
        .sll_halen    = ETH_ALEN,
        .sll_ifindex  = ifIndex,
    };

    char nextMac[ETH_ALEN]={0x00,0x0c,0x29,0xed,0xcb,0x9f};
    //getNextMac(nextMac);
    memcpy(&dest_addr.sll_addr, nextMac, ETH_ALEN);
    int ret = sendto(sockfd,  buf,                           sizeof(struct IPPack), 
                     0,       (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if(ret < 0){
        perror("Error: Send ping failed!\n");
        assert(0);
    }
    printf("*** Sending ICMP to %s ***\n",printIP(ipPack->dstIP));
    icmpTransmitted++;
}

void  recvPing(){
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

char* printIP(uint32_t ip){
    static char tmp[50];
    memset(tmp,0,50);
    inet_ntop(AF_INET, &ip, tmp, INET_ADDRSTRLEN);
    return tmp;
}