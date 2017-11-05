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

#endif // MAC_H
