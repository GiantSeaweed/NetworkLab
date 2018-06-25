#ifndef __TYPE_H__
#define __TYPE_H__
#include <sys/types.h>
typedef unsigned int uint32_t;
typedef unsigned short uint16_t;
typedef unsigned char uint8_t;

#define ETH_ALEN 6
#define IP_ALEN  4
#define HW_TYPE  1   // ethernet:1
#define PROTO_ARP 0x0806
#define PROTO_IP 0x8000
#define ARP_REQUEST 1
#define ARP_REPLY   2
#define ICMP_ECHO_REPLY   0
#define ICMP_ECHO_REQUEST 8
#define IP_ICMP 1


struct IcmpPack{
    uint8_t  type; /* message type */
    uint8_t  code; /* type sub-code */
    uint16_t checksum;
    uint16_t id;
    uint16_t sequence;
    uint8_t  data[56];
};


struct IPPack{
    uint8_t header_length:4,
            version:4;
    uint8_t dscp:6,
            ecn:2;
    uint16_t total_length;
    uint16_t id;
    uint16_t fragment_off:13,
             flags:3;
    uint8_t ttl;        //time to live
    uint8_t protocol;
    uint16_t checksum;
    uint32_t srcIP;
    uint32_t dstIP;
    uint8_t payload[400];

};

struct EthPack
{
    /* data */
    uint8_t dstMacAddr[6];
    uint8_t srcMacAddr[6];
    uint16_t ethType;
    union{
        struct IPPack *ipPack;
        struct ArpPack *arpPack;
    };
    
};


struct EthArpPack{
    //ethernet header
    uint8_t dstMacAddr[6];
    uint8_t srcMacAddr[6];
    uint16_t ethType;

    uint16_t hrdType;
    uint16_t proType;
    uint8_t hrdLen;
    uint8_t proLen;
    uint16_t opcode;
    uint8_t srcHrdAddr[6];
    uint32_t srcProAddr;
    uint8_t dstHrdAddr[6];
    uint32_t dstProAddr;
};

#define MAX_ROUTE_NUM 100
#define MAX_ARPITEM_NUM 100
#define MAX_DEVICE_NUM 100
struct RouteItem
{
    uint8_t destination[16];
    uint8_t gateway[16];
    uint8_t netmask[16];
    uint8_t interface[16];
} routeTable[MAX_ROUTE_NUM];
int routeItemNum = 0;

//the informaiton of the " my arp cache"
struct ArpTableItem{
    uint32_t ipAddr;
    uint8_t macAddr[6];
} ;

// the storage of the device  
struct DeviceItem{
    char interface[14];
    char mac_addr[18];
} device[MAX_DEVICE_NUM]; // the sum of the interfacegot information from configuration file : if.info
int deviceItemNum = 0;
#endif