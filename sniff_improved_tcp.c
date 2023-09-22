#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ether_header *eth_header = (struct ether_header *)packet;

    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ip_packet = (struct ip *)(packet + sizeof(struct ether_header));

        if (ip_packet->ip_p == IPPROTO_TCP) {
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + (ip_packet->ip_hl << 2));

            printf("Ethernet Header:\n");
            printf("   Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                eth_header->ether_shost[0], eth_header->ether_shost[1], eth_header->ether_shost[2],
                eth_header->ether_shost[3], eth_header->ether_shost[4], eth_header->ether_shost[5]);
            printf("   Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                eth_header->ether_dhost[0], eth_header->ether_dhost[1], eth_header->ether_dhost[2],
                eth_header->ether_dhost[3], eth_header->ether_dhost[4], eth_header->ether_dhost[5]);

            printf("IP Header:\n");
            printf("   Source IP: %s\n", inet_ntoa(ip_packet->ip_src));
            printf("   Destination IP: %s\n", inet_ntoa(ip_packet->ip_dst));

            printf("TCP Header:\n");
            printf("   Source Port: %d\n", ntohs(tcp_header->th_sport));
            printf("   Destination Port: %d\n", ntohs(tcp_header->th_dport));

            int data_length = pkthdr->len - sizeof(struct ether_header) - (ip_packet->ip_hl << 2) - (tcp_header->th_off << 2);
            if (data_length > 0) {
                printf("Message Data (First 64 Bytes):\n");
                int i;
                for (i = 0; i < data_length && i < 64; i++) {
                    printf("%02x ", packet[sizeof(struct ether_header) + (ip_packet->ip_hl << 2) + (tcp_header->th_off << 2) + i]);
                }
                printf("\n");
            }

            printf("\n");
        }
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);

    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_close(handle);
    return 0;
}
