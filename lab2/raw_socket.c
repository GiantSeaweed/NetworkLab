#include<stdio.h>
#include<unistd.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<linux/if_ether.h>
#include<linux/in.h>    //definition of ip protocols
#define BUFFER_MAX 2048
void unpack_ip(unsigned char* ip_head);
void unpack_icmp(unsigned char* icmp_head);
void unpack_arp(unsigned char* arp_head);
void unpack_rarp(unsigned char* pld);


int main(){
    int sock_fd;
    int proto;
    int n_read;
    char buffer[BUFFER_MAX];
    char *eth_head;
    char *tcp_head;
    char *ip_head;
    char *udp_head;
    char *icmp_head;
    unsigned char* p;
    unsigned char* type;
    if((sock_fd=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL)))<0){
        printf("error create raw socket\n");
        return -1;
    }
    while(1){
        n_read = recvfrom(sock_fd,buffer,2048,0,NULL,NULL);
        if(n_read < 42){
            printf("error when recv msg \n");
            return -1;
        }
        eth_head = buffer;
        p = eth_head;
        printf("MAC address: %.2x:%02x:%02x:%02x:%02x:%02x ==> %.2x:%02x:%02x:%02x:%02x:%02x\n",
                p[6],p[7],p[8],p[9],p[10],p[11],
                p[0],p[1],p[2],p[3],p[4],p[5]);
        char* data_head = eth_head + 14;
        p = ip_head + 12;
        //printf("IP:%d.%d.%d.%d ==> %d.%d.%d.%d\n",
            //    p[0],p[1],p[2],p[3],p[4],p[5],p[6],p[7]);
        //proto = (ip_head + 9)[0];
        //p = ip_head + 12;
        type = eth_head + 12;
        //printf("Protocol:");
        switch(type[0]){
            case 0x08:{
                if(type[1]==0)
                    unpack_ip(data_head);
                else if(type[1]==6)
                    unpack_arp(data_head);
            }break;
            case 0x80:unpack_rarp(data_head);break;
            default:printf("Please query yourself\n");break;
        }
        
    }
    return -1;
}

void unpack_ip(unsigned char* ip_head){
    printf("----------IP HEADER----------\n");
    unsigned char* p =ip_head;
    int temp = p[0]>>4;
    if(temp == 4)
        printf("IP Version\t: 4\n");
    else if(temp ==6)
        printf("IP Version\t: 6\n");
    temp = (p[0]&0xf)*4;//the number of 32-bit words
    printf("Header length\t: %d\n",temp);
    p+=2;
    temp = (p[0]<<8)+p[1];
    //printf("DEBUG:Total length: %d %d\n",p[0],p[1]);
    printf("Total length\t: %d\n",temp);
    p+=6;
    printf("Time To live\t: %d\n",p[0]);
    int proto = p[1];
    p+=4;
    printf("Src IP Address  : %d.%d.%d.%d\n",
                p[0],p[1],p[2],p[3]);
    p+=4;
    printf("Dest IP Address : %d.%d.%d.%d\n",
                p[0],p[1],p[2],p[3]);
    printf("--------IP HEADER END--------\n");
    switch(proto){
        case IPPROTO_ICMP:unpack_icmp(ip_head+20);break;
        case IPPROTO_IGMP:printf("igmp\n");break;
        case IPPROTO_IPIP:printf("ipip\n");break;
        case IPPROTO_TCP:printf("tcp\n");break;
        case IPPROTO_UDP:printf("udp\n");break;
        default:printf("Pls add choices in unpack_ip\n");
    }
    
    
}

void unpack_icmp(unsigned char* icmp_head){
    printf("Protocol\t: ICMP\n");
    unsigned char* p = icmp_head;
    if(p[0]==8)
        printf("Type\t\t: 8 (Echo (ping) request)\n");
    else if(p[0]==0)
        printf("Type\t\t: 0 (Echo (ping) reply)\n");

    p+=2;
    int temp = (p[0]<<8)+p[1];
    //printf("DEBUG:checksum: %x %x\n",p[0],p[1]);
    printf("Checksum\t: 0x%04x\n",temp);
    printf("-------------------------\n\n");
}
void unpack_arp(unsigned char* arp_head){
    printf("Protocol\t  : ARP \n");
    unsigned char* p = arp_head;
    int temp = (p[0]<<8)+p[1];
    printf("Hardware type\t  : 0x%02x\n",temp);
    p+=2; 
    temp = (p[0]<<8)+p[1];
    printf("Protocol type\t  : 0x%04x\n",temp);

    p+=2;
    printf("Hardware size\t  : %d\n",p[0]);
    p+=1;
    printf("Protocol size\t  : %d\n",p[0]);
    p+=1;
    
    temp = (p[0]<<8)+p[1];
    if(temp == 1)
        printf("Opcode\t\t  : request(1)\n");
    else if(temp == 2)
        printf("Opcode\t\t  : reply(2)\n");
    p+=2;
    
    printf("Sender MAC Address: %.2x:%02x:%02x:%02x:%02x:%02x\n",
                p[0],p[1],p[2],p[3],p[4],p[5]);
    p+=6;
    printf("Sender IP Address : %d.%d.%d.%d\n",
                p[0],p[1],p[2],p[3]);
    p+=4;
    printf("Target MAC Address: %.2x:%02x:%02x:%02x:%02x:%02x\n",
                p[0],p[1],p[2],p[3],p[4],p[5]);
    p+=6;
    printf("Target IP Address : %d.%d.%d.%d\n\n",
                p[0],p[1],p[2],p[3]);
        
}

void unpack_rarp(unsigned char* pld){
    printf("unpacking rarp\n");
}