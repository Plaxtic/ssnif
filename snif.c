
#include "prot.h"

void print_usage(char*);
void print_packets(int);
void filter_IP_packets(int, int);
void print_blue(int);

int main(int argc, char **argv) {

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        if (getuid())
            fprintf(stderr, "ROOT!\n");
        else
            fprintf(stderr, "Error : raw sock creation failed\n");

        return 1;
    }

    int opt;
    int filter = -1;
    while ((opt = getopt(argc, argv, "i:p:bh")) > 0) {

        int eth_proto;
        switch (opt) {
        case 'i':
            if (bind_to_interface(sock, optarg, ETH_P_ALL) < 0) {
                fprintf(stderr, "Cannot use interface '%s'\n", optarg);
                return 1;
            }
            break;

        case 'p':
            to_upper_word(optarg);
            eth_proto = get_eth_proto(optarg);
            if (eth_proto < 0) {

                filter = get_IP_filter(optarg);
                if (filter == NOTPROTO) {
                    fprintf(stderr, "No such protocol: %s\n", optarg);
                    return 1;
                }
                filter_IP_packets(sock, filter);
            } else {
                close(sock);
                sock = socket(AF_PACKET, SOCK_RAW, htons(eth_proto));
                print_packets(sock);
            }
            break;

        case 'b':
            close(sock);
            sock = open_blue_sock(0);
            if (sock < 0) {
                perror("failed to open bluetooth socket");
                return 1;
            }
            print_blue(sock);
            break;

        case 'h':
            print_usage(argv[0]);
            return 0;

        default:
            print_usage(argv[0]);
            return 1;
        }
    }
    print_packets(sock);
    close(sock);
}

void print_blue(int sock) {
    uint8_t *packet = malloc(MAXPACKETSIZ);
    while (1) {

        int packet_size = read(sock, packet, MAXPACKETSIZ);
        if (packet_size  < 0) {
            printf("Error : raw sock read failed\n");
            return;
        }
        printf("%s\n", PACKETFOOT);
        print_payload(packet, packet_size);
        printf("%s\n\n", PACKETFOOT);
    }
}

void filter_IP_packets(int sock, int filter) {

    bool parsable =
        filter == 1 ||
        filter == 2 ||
        filter == 6 ||
        filter == 17;

    uint8_t *packet = malloc(MAXPACKETSIZ);
    while (1) {

        int packet_size = read(sock, packet, MAXPACKETSIZ);
        if (packet_size  < 0) {
            printf("Error : raw sock read failed\n");
            return;
        }

        int eth_proto = ((struct ether_header *)(packet))->ether_type;
        if (ntohs(eth_proto) == ETHERTYPE_IP) {

            int ip_proto = ((struct iphdr *)(packet + sizeof(struct ether_header)))->protocol;
            if (filter == ip_proto) {
                if (parsable) {
                    handle_protocol(packet, packet_size);
                } else {
                    printf(PACKETHEADING, IPproto[filter]);
                    print_payload(packet, packet_size);
                }
            }
        }
    }
}

void print_packets(int sock) {

    uint8_t *packet = malloc(MAXPACKETSIZ);
    while (1) {

        int packet_size = read(sock, packet, MAXPACKETSIZ);
        if (packet_size  < 0) {
            printf("Error : raw sock read failed\n");
            return;
        }

        int eth_proto = ((struct ether_header *)(packet))->ether_type;
        switch (ntohs(eth_proto)) {
        case ETHERTYPE_IP:
            handle_protocol(packet, packet_size);
            break;

        case ETHERTYPE_ARP:
            print_arp(packet, packet_size);
            break;

        default:
            printf(PACKETHEADING, get_eth_name(ntohs(eth_proto)));
            print_payload(packet, packet_size);
            break;
        }
    }
}

void print_usage(char *path) {
    fprintf(stderr, "Usage: %s\n\n\
            -i <interface>          listen on interface\n\
            -p <packet type>        capture only packet type\n\
            -b                      use default bluetooth interface\n\
            -h                      print this help and exit\n\n\
            \
            Packet types:\n\
\n\
            IP:\n\
            ALL, UDP, TCP, ICMP, IGMP\n\
\n\
            ETH:\n\
            ARP, ETC. (see /usr/include/linux/if_ether.h)\n\n", path);
}
