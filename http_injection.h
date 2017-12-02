#ifndef TCP_PACKET_H
#define TCP_PACKET_H
#include <pcap.h>

bool http_injection(pcap_t *fp, const u_char *pkt_data, int pkt_length);
#endif // TCP_PACKET_H
