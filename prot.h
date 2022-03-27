#include <errno.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/sdp.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/igmp.h>
#include <sys/ioctl.h>

#define PACKETHEADING "\n\n****************************%s PACKET****************************\n"
#define PACKETFOOT "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
#define MAXPACKETSIZ 65536
#define MAXTYPESIZ 10
#define NOTPROTO -2

extern char *IPproto[], *ARPproto[];

char *get_op(int);
char *get_eth_name(unsigned int);
int get_IP_filter(char*);
int bind_to_interface(int, char*, int);
int open_blue_sock(int);
int get_eth_proto(char*);
void handle_protocol(uint8_t*, unsigned int);
void print_tcp(uint8_t*,unsigned int);
void print_udp(uint8_t*,unsigned int);
void print_icmp(uint8_t*, unsigned int);
void print_igmp(uint8_t*, unsigned int);
void print_arp(uint8_t*, unsigned int);
void print_payload(uint8_t*, int);
void to_upper_word(char*);

