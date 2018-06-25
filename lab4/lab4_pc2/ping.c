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
void dealPacket(uint8_t* recvBuf, int recvLength);
void getNextMac(char* mac);
char* printIP(uint32_t ip) ;
uint16_t checkSum(unsigned char *addr, int length);

int main(int argc, char* argv[]){
    //printf("Argc : %d\n",argc);
    parseCmd(argc,argv);
    readHostIP();     //get host ip addr from configure.file
    getIfInfo(ifName);//get host mac addr
    //printf("3\n");
    if( (sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0){
          perror("Error:Init Socket Failed!\n");
          assert(0);
    }
    int sequence = 1;
    uint8_t recvBuf[BUFSIZ];
    while(1){
        //sendPing(sequence);
        memset(recvBuf,0,BUFSIZ);
        struct sockaddr_ll addr;
        socklen_t addrLen;
        int recvLength = recvfrom(sockfd,recvBuf,BUFSIZ,0,
                        (struct sockaddr*)&addr,&addrLen);
        
        if(recvLength < 0){
            perror("Error: Receive Failed!");
            assert(0);
        }
        if(addr.sll_hatype !=ARPHRD_ETHER){
            continue;
        }
        dealPacket(recvBuf, recvLength);
        
        //sleep(1);
    }

    return 0;
}

void parseCmd(int argc,char* argv[]){
    if(argc > 2){
        printf("Argc > 1\n");
        exit(0);
    }
    char tmp[20];
    inet_pton(AF_INET, argv[argc-1], (uint8_t*)&dstIP);
   // dstIP = ntohl(atoi(tmp));
    printf("*** Get dstIP from file : %s\n",argv[argc-1]);
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
            //eth1IP = atoi(ip);
        }
        else{
            if (inet_pton(AF_INET, ip, (uint8_t*)&gwIP) == -1)
            {
                printf("Error: Reading host gwIP failed!\n");
                exit(0);
            }
            printf("*** Get Gateway IP: %s ***\n", ip);
           // gwIP = atoi(ip);
        }
    }
    fclose(fp);
}

void getIfInfo(const char *ifName)
{
    struct ifreq req;
    memset(&req, 0, sizeof(struct ifreq));

    if(strlen(ifName) > IFNAMSIZ-1){
        perror("Error: getIfInfo, strlen(ifName) too large\n");
        assert(0);
    }
    strcpy(req.ifr_name, ifName);//, IFNAMSIZ - 1);
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
    printf("ifIndex = %d\n",ifIndex);

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
                0,  (struct sockaddr *)&destAddr, sizeof(struct sockaddr_ll)  );
    
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

    char nextMac[ETH_ALEN]={0x00,0x0c,0x29,0x45,0x09,0x1b};
    //getNextMac(nextMac);
    memcpy(&dest_addr.sll_addr, nextMac, ETH_ALEN);
    int ret = sendto(sockfd,  buf,                           sizeof(struct IPPack), 
                     0,       (struct sockaddr *)&dest_addr, sizeof(struct sockaddr_ll));
    if(ret < 0){
        perror("Error: Send ping failed!\n");
        assert(0);
    }
    printf("*** Sending ICMP to %s ***\n",printIP(ipPack->dstIP));
    icmpTransmitted++;
}

void  dealPacket(uint8_t* recvBuf, int recvLength){
    struct EthPack* ethPack = (struct EthPack*)recvBuf;
    //printf("Dealing\n");
    //printf("%04x %04x\n",ethPack->ethType,PROTO_IP);
    if(ethPack->ethType == htons(ETH_P_ARP)){
        printf("Receing an ARP packet!\n");
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
                char nextMac[ETH_ALEN]={0x00,0x0c,0x29,0x45,0x09,0x1b};//router2 ens38
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



/*
void fillIcmpHdr(struct icmphdr *icmp_hdr, int seq)
{
    icmp_hdr->type = ICMP_ECHO; //ICMP_ECHO REPLY=0(Reply); ICMP_ECHO=8(Request)
    icmp_hdr->code = 0;
    icmp_hdr->checksum = 0; //clear the checkSum field
    //  htons():(unsigned short) Host Order ==> Network Order *
    icmp_hdr->un.echo.id = htons(getpid());
    icmp_hdr->un.echo.sequence = htons(seq);

    gettimeofday((struct timeval *)((char *)icmp_hdr + ICMP_HEAD_LEN), NULL);
    // * fill the checkSum field *
    icmp_hdr->checksum = checkSum((unsigned char *)icmp_hdr, ICMP_PACKET_LEN);
}*/
/*
void icmpRequest(int fd, int seq)
{
    fillIcmpHdr((struct icmphdr *)buff, seq);
     * sendto(int sockfd, const void *buf,                size_t len,
     *        int flags,  const struct sockaddr*dst_addr, socklen_t addrlen);
     *
    int addrlen = sizeof(struct sockaddr_in);
    int req = sendto(fd, buff, ICMP_PACKET_LEN, 0, (struct sockaddr *)&dst_addr, addrlen);
    assert(req != -1);
}*/
/*
int icmpReply(int fd)
{
    //    int addrlen = sizeof(struct sockaddr_in);
    int rcv = recvfrom(fd, recvbuff, RECV_MAX_SIZE, 0, NULL, NULL);
    if (rcv == -1)
        return 0; //false

    struct ip *ip = (struct ip *)(recvbuff);
    struct icmphdr *icmp_hdr = (struct icmphdr *)(recvbuff + sizeof(struct iphdr));
    struct timeval *send_time = (struct timeval *)(recvbuff + sizeof(struct iphdr) + ICMP_HEAD_LEN);

    struct timeval now_time;
    gettimeofday(&now_time, NULL);
    //printf("now:%ld %ld; send:%ld %ld\n",now_time.tv_sec,now_time.tv_usec,
    //                            send_time->tv_sec,send_time->tv_usec);
    //printf("%d %d\n",    (ip->ip_len),(short)ip->ip_hl);
    printf("%d bytes from %s:\t icmp_seq=%d\t ttl=%d\t   time=%.2fms\n",
           ntohs(ip->ip_len) - ip->ip_hl * 4, // ntohs()      : (the unsigned short) Network Order ==> ost Order
           inet_ntoa(dst_addr.sin_addr),      // inet_ntoa(): Data in Network Order ==> IP Address(NUMS_AND_DOTS)
           ntohs(icmp_hdr->un.echo.sequence),
           ip->ip_ttl,
           (double)(now_time.tv_sec - send_time->tv_sec) * 1000 + (double)(now_time.tv_usec - send_time->tv_usec) / 1000);
    return 1; //true
}
*/
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

char* printIP(uint32_t ip){
    static char tmp[50];
    inet_ntop(AF_INET, &ip, tmp, INET_ADDRSTRLEN);
    return tmp;
}