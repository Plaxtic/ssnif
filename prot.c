#ifndef PROT_H
#define PROT_H

#include "prot.h"
#include "protocol_data.h"

void handle_protocol(uint8_t *packet, unsigned int size) {
    int protocol = ((struct iphdr *)(packet + 
                sizeof(struct ether_header)))->protocol;

    if (protocol < 0 || protocol > 255) {
        printf("Error : unrecognised protocol %d\n", protocol);
        return;
    }

    switch (protocol) {
        case 1:
            print_icmp(packet, size);
            break;

        case 2:
            print_igmp(packet, size);
            break;

        case 6:
            print_tcp(packet, size);
            break;

        case 17:
            print_udp(packet, size);
            break;

        default:
            printf("Cannot parse %s packet\n\n", IPproto[protocol]);
            print_payload(packet, size);
            break;
    }
}

int open_blue_sock(int dev) {

    // Create HCI socket
    int blue = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
    if (blue < 0) {
        return -1;
    }

    int opt = 1;
    if (setsockopt(blue, SOL_HCI, HCI_DATA_DIR, &opt, sizeof(opt)) < 0) {
        close(blue);
        return -1;
    }
    opt = 1;
    if (setsockopt(blue, SOL_HCI, HCI_TIME_STAMP, &opt, sizeof(opt)) < 0) {
        close(blue);
        return -1;
    }

    // Setup filter
    struct hci_filter flt;
    hci_filter_clear(&flt);
    hci_filter_all_ptypes(&flt);
    hci_filter_all_events(&flt);
    if (setsockopt(blue, SOL_HCI, HCI_FILTER, &flt, sizeof(flt)) < 0) {
        close(blue);
        return -1;
    }

    // Bind socket to the HCI device
    struct sockaddr_hci addr;
    memset(&addr, 0, sizeof(addr));
    addr.hci_family = AF_BLUETOOTH;
    addr.hci_dev    = dev;
    if (bind(blue, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        printf("Can't attach to device hci %d. %s(%d)\n",
                dev, strerror(errno), errno);
        close(blue);
        return -1;
    }
    return blue;
}

int bind_to_interface(int sock, char *dev, int protocol) {

    //copy device name to ifr
    struct ifreq ifr = {0}; 
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    if (ioctl(sock, SIOCGIFINDEX , &ifr) < 0) {
        return -1;
    }

    struct sockaddr_ll sll = {0};
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(protocol);

    return bind(sock, (struct sockaddr *)&sll , sizeof(sll));
}

int get_eth_proto(char *proto_name) {
    for (int i = 0; ETHproto[i].name != NULL; i++)
        if (strncmp(ETHproto[i].name, proto_name, MAXETHPROTONAME) == 0)
            return ETHproto[i].proto;

    return -1;
}

char *get_eth_name(unsigned int proto) {
    for (int i = 0; ETHproto[i].name != NULL; i++)
        if (ETHproto[i].proto == proto)
            return ETHproto[i].name;

    return "UNRECOGNISED";
}

int get_IP_filter(char *proto) {
    for (int i = 0; IPproto[i] != NULL; i++)
        if (strncmp(IPproto[i], proto, MAXTYPESIZ) == 0)
            return i;

    return -2;
}

static void print_mac(uint8_t mac[ETH_ALEN]) {
    for (int i = 0; i < ETH_ALEN-1; ++i)
        printf("%.2X-", mac[i]);

    printf("%.2X\n", mac[ETH_ALEN-1]);
}

void to_upper_word(char *s) { 
    while (*s != '\0') {
        *s = toupper(*s);
        s++;
    }
}

void print_eth(uint8_t *packet) {

    // Handle ethernet header by casting buffer
    struct ether_header *eth = (struct ether_header *)(packet);

    printf("\nEthernet Header\n");
    printf("\t|-Source Address           :  ");
    print_mac(eth->ether_shost); 
    printf("\t|-Destination Address      :  "); 
    print_mac(eth->ether_dhost);
    printf("\t|-EtherType                :  %d\n", 
            ntohs(eth->ether_type));
}

int print_eth_and_ip(uint8_t *packet) {
    print_eth(packet);

    // Increment buffer over ethernet header to parse ip header
    struct iphdr *ip = (struct iphdr *)(packet
            + sizeof(struct ether_header));

    struct in_addr src, dst;
    src.s_addr = ip->saddr;
    dst.s_addr = ip->daddr;

    printf("\nIP Header\n");
    printf("\t|-Version                  :  %u\n", ip->version);
    printf("\t|-Internet Header Length   :  %d DWORDS or %d Bytes\n",
            (unsigned int)ip->ihl, 
            ((unsigned int)(ip->ihl))*4);
    printf("\t|-Type Of Service          :  %u\n", ip->tos);
    printf("\t|-Total Length             :  %d Bytes\n", 
            ntohs(ip->tot_len));
    printf("\t|-Identification           :  %d\n", ntohs(ip->id));
    printf("\t|-Time To Live             :  %u\n", ip->ttl);
    printf("\t|-Protocol                 :  %u\n", ip->protocol);
    printf("\t|-Header Checksum          :  %d\n", ntohs(ip->check));
    printf("\t|-Source IP                :  %s\n", inet_ntoa(src));
    printf("\t|-Destination IP           :  %s\n", inet_ntoa(dst));

    return ip->ihl*4;
}

void print_tcp(uint8_t *packet, unsigned int packet_size) {
    printf(PACKETHEADING, "TCP");

    int iphdrlen = print_eth_and_ip(packet);

    // Increment buffer over ip header to parse TCP
    struct tcphdr *tcp = (struct tcphdr*)(packet + iphdrlen
            + sizeof(struct ether_header));

    printf("\nTCP header\n");
    printf("\t|-Source Port              :  %d\n", ntohs(tcp->source));
    printf("\t|-Destination Port         :  %d\n", ntohs(tcp->dest));
    printf("\t|-Sequence Number          :  %d\n", ntohs(tcp->seq));
    printf("\t|-Checksum                 :  %d\n", ntohs(tcp->check));
    printf("\t|-Window                   :  %d\n", ntohs(tcp->window));
    printf("\t|-Urgent Pointer           :  %#x\n", ntohs(tcp->urg_ptr));
    printf("\t|-ACK Number               :  %d\n", ntohs(tcp->ack_seq));
    printf("\t|--------flags-------\n");
    printf("\t\t|-Urgent                 :  %d\n", ntohs(tcp->urg));
    printf("\t\t|-ACK                    :  %d\n", ntohs(tcp->ack));
    printf("\t\t|-Push                   :  %d\n", ntohs(tcp->psh));
    printf("\t\t|-RST                    :  %d\n", ntohs(tcp->rst));
    printf("\t\t|-SYN                    :  %d\n", ntohs(tcp->syn));
    printf("\t\t|-Finish                 :  %d\n", ntohs(tcp->fin));

    // Print payload 
    uint8_t *data = (packet + iphdrlen + sizeof(struct ether_header) 
            + sizeof(struct udphdr));
    int data_size = packet_size - (iphdrlen + sizeof(struct ether_header)
            + sizeof(struct udphdr));

    printf("\n\nPayload\n\n");
    print_payload(data, data_size);
    printf("%s\n\n", PACKETFOOT);
}

void print_udp(uint8_t *packet, unsigned int packet_size) {
    printf(PACKETHEADING, "UDP");

    int iphdrlen = print_eth_and_ip(packet);

    // Increment buffer over ip header to parse UDP
    struct udphdr *udp = (struct udphdr*)(packet + iphdrlen 
            + sizeof(struct ether_header));

    printf("\nUDP header\n");
    printf("\t|-Source Port              :  %d\n", ntohs(udp->source));
    printf("\t|-Destination Port         :  %d\n", ntohs(udp->dest));
    printf("\t|-UDP Length               :  %d\n", ntohs(udp->len));
    printf("\t|-UDP Checksum             :  %d\n", ntohs(udp->check));

    // Print payload 
    uint8_t *data = (packet + iphdrlen + sizeof(struct ether_header) 
            + sizeof(struct udphdr));
    int data_size = packet_size - (iphdrlen + sizeof(struct ether_header) 
            + sizeof(struct udphdr));

    printf("\n\nPayload\n\n");
    print_payload(data, data_size);
    printf("%s\n\n", PACKETFOOT);
}

void print_icmp(uint8_t *packet, unsigned int packet_size) {
    printf(PACKETHEADING, "ICMP");

    int iphdrlen = print_eth_and_ip(packet);

    // Increment buffer over ip header to parse ICMP
    struct icmphdr *icmp = (struct icmphdr*)(packet + iphdrlen + sizeof(struct ether_header));

    printf("\nICMP header\n");
    printf("\t|-Type                     :  %d\n", ntohs(icmp->type));
    printf("\t|-Code                     :  %d\n", ntohs(icmp->code));
    printf("\t|-Checksum                 :  %d\n", ntohs(icmp->checksum));
    printf("\t|-Gateway                  :  %d\n",
            ntohs(icmp->un.gateway));
    printf("\t|--------Echo-------\n");
    printf("\t\t|-ID                 :  %d\n", ntohs(icmp->un.echo.id));
    printf("\t\t|-Sequence           :  %d\n", ntohs(icmp->un.echo.sequence));
    printf("\t|--------Frag-------\n");
    printf("\t\t|-MTU                :  %d\n", ntohs(icmp->un.frag.mtu));

    // Print payload 
    uint8_t *data = (packet + iphdrlen + sizeof(struct ether_header) 
            + sizeof(struct icmphdr));
    int data_size = packet_size - (iphdrlen + sizeof(struct ether_header) 
            + sizeof(struct icmphdr));

    printf("\n\nPayload\n\n");
    print_payload(data, data_size);

    printf("%s\n\n", PACKETFOOT);
}

void print_igmp(uint8_t *packet, unsigned int packet_size) {
    printf(PACKETHEADING, "IGMP");

    int iphdrlen = print_eth_and_ip(packet);

    // Increment buffer over ip header to parse IGMP
    struct igmp *igmphdr = (struct igmp*)(packet + iphdrlen
            + sizeof(struct ether_header));

    printf("\nIGMP header\n");
    printf("\t|-Type                     :  %d\n",
            ntohs(igmphdr->igmp_type));
    printf("\t|-Code                     :  %d\n",
            ntohs(igmphdr->igmp_code));
    printf("\t|-Checksum                 :  %d\n",
            ntohs(igmphdr->igmp_cksum));
    printf("\t|-Group                    :  %d\n",
            ntohs(igmphdr->igmp_group.s_addr));

    // Print payload 
    uint8_t *data = (packet + iphdrlen + sizeof(struct ether_header)
            + sizeof(struct igmp));
    int data_size = packet_size - (iphdrlen
            + sizeof(struct ether_header) + sizeof(struct igmp));

    printf("\n\nPayload\n\n");
    print_payload(data, data_size);
    printf("%s\n\n", PACKETFOOT);
}

void print_arp(uint8_t *packet, unsigned int packet_size) {
    printf(PACKETHEADING, "ARP");

    print_eth(packet); 

    // Increment buffer over ip header to parse arp
    struct ether_arp *arp = (struct ether_arp *)(packet
            + sizeof(struct ether_header));

    int op = ntohs(arp->ea_hdr.ar_op);

    printf("\nARP header\n");
    printf("\t|-Source MAC               :  "); 
    print_mac(arp->arp_sha);
    printf("\t|-Destination MAC          :  "); 
    print_mac(arp->arp_tha);
    printf("\t|-Source protocol          :  %d.%d.%d.%d\n", 
            arp->arp_spa[0],
            arp->arp_spa[1],
            arp->arp_spa[2],
            arp->arp_spa[3]);
    printf("\t|-Target protocol          :  %d.%d.%d.%d\n", 
            arp->arp_tpa[0],
            arp->arp_tpa[1],
            arp->arp_tpa[2],
            arp->arp_tpa[3]);
    printf("\t|-Hardware Type            :  %d\n", 
            ntohs(arp->ea_hdr.ar_hrd));
    printf("\t|-Protocol Type            :  %d\n", 
            ntohs(arp->ea_hdr.ar_pro));
    printf("\t|-Op code                  :  %d (%s)\n", op, get_op(op));
    printf("%s\n\n", PACKETFOOT);
}

void print_payload(uint8_t *data, int data_size) {
    int j, i;

    for (i = 0, j = 0; i < data_size; i++) {
        printf("%.2X ", data[i]);

        // if end of line, decode line
        if (i != 0 && (i+1)%16 == 0) {
            printf("|");

            for (j = i-16; j < i; j++)
                printf("%c", isprint(data[j]) ? data[j] : '.');

            printf("|\n");
        }

        // if end of data, decode tail
        if (i == data_size-1 && (i+1)%16 != 0) {
            int left = j+16;

            for (int k = i; k < left; k++)
                printf("   ");

            printf("|");
            while (j++ < i)
                printf("%c", isprint(data[j]) ? data[j] : '.');

            for (int k = i; k < left; k++)
                printf(" ");

            printf("|\n");
            break;
        }
    }
}
#endif
