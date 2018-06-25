#include<stdio.h>     //printf
#include<stdlib.h>
//#include<string.h>

#include<unistd.h>            //close
#include<sys/socket.h>
#include<netinet/in.h>        //struct sockaddr_in
#include<sys/time.h>         //gettimeofday; struct timeval
#include<arpa/inet.h>        //htonl.htons.ntohl.ntohs
#include<netinet/ip_icmp.h> //struct icmphdr
#include<assert.h>

#define ICMP_HEAD_LEN    sizeof(struct icmphdr)
#define ICMP_PACKET_LEN  (ICMP_HEAD_LEN + sizeof(struct timeval))
#define RECV_MAX_SIZE    (2048)

struct sockaddr_in dst_addr;//addresss information
struct timeval begin_time;
char buff[ICMP_PACKET_LEN];
char recvbuff[RECV_MAX_SIZE];
char*DST_IP;
int transmitted = 0;
int received    = 0;

int initSocket(char* dst_ip);
void icmpRequest(int fd, int seq);
int icmpReply(int fd);
void closeSocket(int fd);
unsigned short checkSum(unsigned char* addr, int length);

int main(int argc,char* argv[]){
    if(argc < 2){
        printf("Incorrect Format of Input!\n");
        assert(0);
    }
    unsigned int count = -1;
    int sequence = 1;
    int ch;
    int i=0;
    printf("How many ICMP packets do you want to send? \n");
    scanf("%d",&count);
    int socket_fd = initSocket(argv[argc-1]);
    DST_IP = argv[argc-1];

    gettimeofday(&begin_time,NULL);
    for(; i < count; i++){
        icmpRequest(socket_fd,sequence++);
        transmitted++;
        if(icmpReply(socket_fd))
            received++;
        else
            assert(0);
        sleep(1);
    }
    closeSocket(socket_fd);
    return 0;
}

int initSocket(char* dst_ip){
    int socket_fd = socket(AF_INET, SOCK_RAW,IPPROTO_ICMP);
    assert(socket_fd!=-1);
    dst_addr.sin_family      = AF_INET;
    dst_addr.sin_addr.s_addr = inet_addr(dst_ip);
    return socket_fd;
}

void fillIcmpHdr(struct icmphdr *icmp_hdr, int seq){
    icmp_hdr->type = ICMP_ECHO;
    icmp_hdr->code = 0;
    icmp_hdr->checksum = 0;
    icmp_hdr->un.echo.id = htons(getpid());
    icmp_hdr->un.echo.sequence = htons(seq);

    gettimeofday((struct timeval*)((char*)icmp_hdr+ICMP_HEAD_LEN),NULL);
    icmp_hdr->checksum = checkSum((unsigned char*)icmp_hdr, ICMP_PACKET_LEN);
}    

void icmpRequest(int fd, int seq){
    fillIcmpHdr((struct icmphdr*)buff, seq);
    /* sendto(int sockfd, const void *buf, size_t len,
     *          int flags, const struct sockaddr*dst_addr,socklen_t addrlen);
     */
    int addrlen = sizeof(struct sockaddr_in);
    int req     = sendto(fd, buff, ICMP_PACKET_LEN, 0, (struct sockaddr*)&dst_addr, addrlen);
    assert(req!=-1);
}

int icmpReply(int fd){
    int addrlen = sizeof(struct sockaddr_in);
    int rcv = recvfrom(fd, recvbuff, RECV_MAX_SIZE, 0, NULL, NULL);
    if(rcv == -1)
        return 0;//false

    struct ip *ip = (struct ip*)(recvbuff);
    struct icmphdr *icmp_hdr  = (struct icmphdr*)(recvbuff + sizeof(struct iphdr));
    struct timeval *send_time = (struct timeval*)(recvbuff + sizeof(struct iphdr)+ICMP_HEAD_LEN);

    struct timeval now_time;
    gettimeofday(&now_time, NULL);
    //printf("now:%ld %ld; send:%ld %ld\n",now_time.tv_sec,now_time.tv_usec,
    //                            send_time->tv_sec,send_time->tv_usec);
    //printf("%d %d\n",    (ip->ip_len),(short)ip->ip_hl);
    printf("%d bytes from %s:\t icmp_seq=%d\t ttl=%d\t   time=%.2fms\n",
            ntohs(ip->ip_len)-ip->ip_hl*4, 
            inet_ntoa(dst_addr.sin_addr),
            ntohs(icmp_hdr->un.echo.sequence),
            ip->ip_ttl,
            (double)(now_time.tv_sec-send_time->tv_sec)*1000+(double)(now_time.tv_usec-send_time->tv_usec)/1000);
    return 1;//true
}

void closeSocket(int fd){
    close(fd);
}

unsigned short checkSum(unsigned char* addr, int length){
    unsigned short* p = (unsigned short*)addr;
    unsigned int sum = 0;
    while(length > 1){
        sum += *p;
        p++;
        length = length - 2;
    }
    if(length == 1){
        sum += *p;
    }
    
    while((sum>>16)!=0){
        sum = (sum>>16) + (sum & 0xffff);
    }
    return (unsigned short)(~sum);
}