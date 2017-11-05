#include <iostream>
#include "mac.h"
#include "key_value.h"
#include <pcap.h>
#include <cstdio>
#include <map>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>


#define PCAP_OPENFLAG_PROMISCUOUS 1   // Even if it isn't my mac, receive packet

using namespace std;

struct pcap_pkthdr *pkt_header;
struct user_info_value uiv;

struct ether_header *eh;
struct ip *iph;
struct tcphdr *tcph;


char errbuf[PCAP_ERRBUF_SIZE];

uint8_t mac_changer(const char *ipm,uint8_t *opm) //ipm = inputmac, opm = outputmac
{
   return sscanf(ipm,"%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",&opm[0],&opm[1],&opm[2],&opm[3],&opm[4],&opm[5]);    //%x cause an error, fix to %2hhx
}
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
            while(true)
            {
                while((res=pcap_next_ex(fp,&pkt_header,&pkt_data))>=0)
                {
                    if(res == 0)continue;
                    pkt_length = pkt_header->len;

                    eh = (struct ether_header*)pkt_data;

                    if( memcmp(eh->ether_dhost,ap_mac,6) == 0 )//
                    {
                        memcpy(user_mac.mac_address,eh->ether_shost,6);
                        if((ui_iter = user_info.find(user_mac)) != user_info.end())
                        {
                            break;
                            //생성시간과 현재 시간을 비교하는 함수를 사용해서 time 값을 변경시킬 예정
                        }
                        else
                        {
                            uiv.time = 0;
                        }
                        user_info.insert(pair<Mac, user_info_value>(user_mac,uiv));
                    }
                    else if(memcmp(eh->ether_shost,ap_mac,6) == 0)
                    {
                        memcpy(user_mac.mac_address,eh->ether_dhost,6);
                        if((ui_iter = user_info.find(user_mac)) != user_info.end())
                        {
                            break;
                            //생성시간과 현재 시간을 비교하는 함수를 사용해서 time 값을 변경시킬 예정
                        }
                        else
                        {
                            uiv.time = 0;
                        }
                        user_info.insert(pair<Mac, user_info_value>(user_mac,uiv));
                    }
                    pkt_data += sizeof(struct ether_header);
                    pkt_length -= sizeof(struct ether_header);

                    system("clear");
                    cout<<"User_Mac\t\tTime"<<endl;
                    for(ui_iter = user_info.begin(); ui_iter!=user_info.end(); advance(ui_iter,1))
                    {
                        for(i=0;i<5;i++)
                            printf("%02x:",ui_iter->first.mac_address[i]); //beacon info key(bssid)
                        printf("%02x\t",ui_iter->first.mac_address[5]);
                        printf("%d\t",ui_iter->second.time);
                        cout<<endl;
                    }

                }
            }
        }
    }

    return 0;
}
