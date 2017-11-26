#include "http_injection.h"
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include <iostream>

#pragma pack(push,1)
struct rst{
    struct ether_header rst_eh;
    struct ip rst_iph;
    struct tcphdr rst_tcph;
    u_char *rst_tcp_data;
};
struct fin{
    struct ether_header *feh;
    struct ip *fiph;
    struct tcphdr *ftcph;
    u_char *ftcp_data;
};
#pragma pack(pop)

bool http_injection(pcap_t *fp,const u_char *pkt_data,int pkt_length){
    struct rst rst;
    struct ether_header *rst_eh = &rst.rst_eh;
    struct ip *rst_iph = &rst.rst_iph;
    struct tcphdr *rst_tcph = &rst.rst_tcph;

    struct ether_header *eh;
    struct ip *iph;
    struct tcphdr *tcph;

    eh = (struct ether_header*)pkt_data;
    memcpy(rst_eh,eh,sizeof(struct ether_header));
    pkt_data += sizeof(struct ether_header);
    pkt_length -= sizeof(struct ether_header);

    iph = (struct ip*)pkt_data;
    memcpy(rst_iph,iph,iph->ip_hl*4);
    rst_iph->ip_tos = 0x82d;    //2093

    return true;
}
