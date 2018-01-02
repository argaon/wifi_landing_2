#include "mac.h"
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <cstdio>
#include <string.h>
#include <ifaddrs.h>
#include <sys/types.h>
#include <arpa/inet.h>

Mac::Mac()
{

}
uint8_t mac_changer(const char *ipm,uint8_t *opm) //ipm = inputmac, opm = outputmac
{
   return sscanf(ipm,"%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",&opm[0],&opm[1],&opm[2],&opm[3],&opm[4],&opm[5]);    //%x cause an error, fix to %2hhx
}
void get_my_addr(const char*ifname,char* outputmyip,uint8_t*outputmymac)
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if(s < 0)
        perror("socket fail");
    struct ifreq ifr;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    if(ioctl(s, SIOCGIFHWADDR, &ifr) < 0)
        perror("ioctl fail");
    memcpy(outputmymac,ifr.ifr_hwaddr.sa_data,6);

    struct ifaddrs * ifAddrStruct=NULL;
    struct ifaddrs * ifa=NULL;
    void * tmpAddrPtr=NULL;

    getifaddrs(&ifAddrStruct);
    for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (!ifa->ifa_addr)
        {
            continue;
        }
        if (ifa->ifa_addr->sa_family == AF_INET)
        { // check it is IP4
            if(strcmp(ifa->ifa_name,ifname)==0)
            {
                tmpAddrPtr=&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
                inet_ntop(AF_INET, tmpAddrPtr, outputmyip, INET_ADDRSTRLEN);
            }
        }
    }
}
