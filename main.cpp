#include <iostream>
#include "mac.h"
#include <pcap.h>
#include <cstdio>
#include <map>
#include <string.h>

#define PCAP_OPENFLAG_PROMISCUOUS 1   // Even if it isn't my mac, receive packet

using namespace std;

struct pcap_pkthdr *pkt_header;

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

            pcap_t *fp;
            if((fp= pcap_open_live(dev, BUFSIZ, PCAP_OPENFLAG_PROMISCUOUS , 1, errbuf)) == NULL)
                {
                    fprintf(stderr,"Unable to open the adapter. %s is not supported by Pcap\n", dev);
                }
    }

    return 0;
}
