#include <iostream>
#include "mac.h"
#include "key_value.h"
#include <pcap.h>
#include <cstdio>
#include <map>
#include <string.h>
#include <time.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <regex>

#define PCAP_OPENFLAG_PROMISCUOUS 1   // Even if it isn't my mac, receive packet

using namespace std;

struct pcap_pkthdr *pkt_header;
struct ether_header *eh;
struct ip *iph;
struct tcphdr *tcph;

struct user_info_value uiv;
struct tm *t;

regex re("GET([^\n]*)"); //GET 으로 시작해서 HTTP/1.1로 끝나는 문자열


char errbuf[PCAP_ERRBUF_SIZE];

uint8_t mac_changer(const char *ipm,uint8_t *opm) //ipm = inputmac, opm = outputmac
{
   return sscanf(ipm,"%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",&opm[0],&opm[1],&opm[2],&opm[3],&opm[4],&opm[5]);    //%x cause an error, fix to %2hhx
}
void print_time(time_t input_time)
{
    time_t now;
    int tm_hour, tm_min, tm_sec;
    time(&now);
    double diff_t = difftime(now,input_time);
    tm_hour = diff_t / (60*60);
    diff_t -= ( tm_hour *60 *60);
    tm_min = diff_t / 60;
    diff_t -= ( tm_min *60);
    tm_sec = diff_t;

    printf("%d시간 %d분 %d초",tm_hour,tm_min,tm_sec);
}
/*
void send_packet(pcap_t *fp){
    struct pcap_pkthdr *pkt_header;
    const u_char *pkt_data;
    int res;
    while((res=pcap_next_ex(fp,&pkt_header,&pkt_data))>=-1)
    {
        if(res == 0)continue;
        pkt_data += sizeof(struct ether_header)+iph->ip_hl*4;
        tcph = (struct tcphdr*)pkt_data;
        tcph->th_flags = 0x11;
        pkt_data -= sizeof(struct ether_header)+iph->ip_hl*4;
        if(pcap_sendpacket(fp,pkt_data,pkt_header->len)!=0)
            {
                fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(fp));
            }
        else
        {
            break;
        }
    }
}
*/
int main(int argc, char *argv[])
{
    char *dev =  argv[1];
    uint8_t ap_mac[6];
    mac_changer(argv[2],ap_mac);

    map<Mac,user_info_value>user_info;
    map<Mac,user_info_value>::iterator ui_iter;

    Mac user_mac;

    if(argc < 3)
        {
            printf("Input argument error!\n");
            if (dev == NULL)
            {
                printf("Input your <dev><AP_Mac_Address>\n");
                printf("EX : Wlan1 AA:BB:CC:DD:EE:FF");
                exit(1);
            }
        }
        else
        {
        printf("DEV : %s\n", dev);
        printf("AP_MAC : %s\n",argv[2]);

        const u_char *pkt_data;
        int res;
        int pkt_length;
        int i;

        pcap_t *fp;
        if((fp= pcap_open_live(dev, BUFSIZ, PCAP_OPENFLAG_PROMISCUOUS , 1, errbuf)) == NULL)
            {
                fprintf(stderr,"Unable to open the adapter. %s is not supported by Pcap\n", dev);
            }
        else
        {
            while((res=pcap_next_ex(fp,&pkt_header,&pkt_data))>=-1)
            {
                if(res == 0)continue;
                if(res == -1)
                {
                    printf("%s is down, after 1sec, restart!\n",dev);
                    sleep(1);
                    if((fp= pcap_open_live(dev, BUFSIZ, PCAP_OPENFLAG_PROMISCUOUS , 1, errbuf)) == NULL)fprintf(stderr,"Unable to open the adapter. %s is not supported by Pcap\n", dev);
                }
                else
                {
                    pkt_length = pkt_header->len;

                    eh = (struct ether_header*)pkt_data;

                    if(memcmp(eh->ether_dhost,ap_mac,6) == 0 || memcmp(eh->ether_shost,ap_mac,6) ==0)
                    {
                        if(memcmp(eh->ether_dhost,ap_mac,6) == 0)
                            memcpy(user_mac.mac_address,eh->ether_shost,6);
                        else
                            memcpy(user_mac.mac_address,eh->ether_dhost,6);
                        pkt_data += sizeof(struct ether_header);
                        pkt_length -= sizeof(struct ether_header);

                        if((ui_iter = user_info.find(user_mac)) != user_info.end())
                        {
                            time_t now;
                            int tm_hour;
                            time(&now);
                            double diff_t = difftime(now,ui_iter->second.time);
                            tm_hour = diff_t / (60*60);
                            diff_t -= ( tm_hour *60 *60);

                            //if(tm_hour>3)
                            if(true)
                            {
                                uint16_t etype = ntohs(eh->ether_type);
                                if(etype == ETHERTYPE_IP)
                                {
                                    iph = (struct ip*)pkt_data;
                                    pkt_data += iph->ip_hl*4;
                                    pkt_length -= iph->ip_hl*4;
                                    if(iph->ip_p == IPPROTO_TCP)
                                    {
                                        tcph = (struct tcphdr*)pkt_data;
                                        pkt_data += tcph->doff*4;
                                        pkt_length -= tcph->doff*4;
                                        if(pkt_length >0)
                                        {
                                            string output(reinterpret_cast<char const*>(pkt_data), pkt_length);
                                            smatch m;
                                            bool match = regex_search(output,m,re);
                                            if((match))
                                            {
                                                tcph->th_flags = 0x11;
                                                pkt_data -= sizeof(struct ether_header)+iph->ip_hl*4+tcph->doff*4;
                                                if(pcap_sendpacket(fp,pkt_data,pkt_header->len)!=0)
                                                {
                                                    fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(fp));
                                                }
                                                cout<<"SEND_FIN_PACKET"<<endl;
                                            }
                                        }
                                    }

                                }
                            }
                        }
                        else
                        {
                            time(&uiv.time);
                            user_info.insert(pair<Mac, user_info_value>(user_mac,uiv));
                        }   //이미 등록이 되어있는 지 조건문
                    }   //ap mac주소가 일치하는지 조건문
                }
                /*
                sleep(1);
                system("clear");
                cout<<"User_Mac\t\tAfter Connection Time"<<endl;
                for(ui_iter = user_info.begin(); ui_iter!=user_info.end(); advance(ui_iter,1))
                {
                    for(i=0;i<5;i++)
                        printf("%02x:",ui_iter->first.mac_address[i]); //beacon info key(bssid)
                    printf("%02x\t",ui_iter->first.mac_address[5]);
                    print_time(ui_iter->second.time);
                    cout<<endl;
                }
                */

            }   //pcap_open_live 함수 while문
        }
    }
    return 0;
}
