#ifndef MAC_H
#define MAC_H
#include <map>

class Mac
{
  public:
    uint8_t mac_address[6];

    // compare
    bool operator <(const Mac &_mac) const {
        return std::tie(mac_address[0], mac_address[1], mac_address[2], mac_address[3], mac_address[4], mac_address[5])
                < std::tie(_mac.mac_address[0], _mac.mac_address[1], _mac.mac_address[2], _mac.mac_address[3], _mac.mac_address[4], _mac.mac_address[5]);
    }
    Mac();
};
uint8_t mac_changer(const char *ipm,uint8_t *opm);
void get_my_addr(const char*ifname,char* outputmyip,uint8_t*outputmymac);
#endif // MAC_H
