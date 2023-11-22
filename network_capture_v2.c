#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

int packet_count = 0;  // 패킷 카운터를 위한 전역 변수

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ether_header *eth_header;
    struct ip *ip_header;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    struct icmphdr *icmp_header;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    packet_count++;  // 패킷을 받을 때마다 카운터 증가

    eth_header = (struct ether_header *)packet;
    printf("[+] PACKET %d\n", packet_count);
    printf("\t┝ MAC Source Address: %s\n", ether_ntoa((struct ether_addr *)eth_header->ether_shost));
    printf("\t┝ MAC Destination Address: %s\n", ether_ntoa((struct ether_addr *)eth_header->ether_dhost));

    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        ip_header = (struct ip *)(packet + ETHER_HDR_LEN);
        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

        printf("\t┝ Source IP Address: %s\n", src_ip);
        printf("\t┝ Destination IP Address: %s\n", dst_ip);

        switch(ip_header->ip_p) {
            case IPPROTO_TCP:
                tcp_header = (struct tcphdr *)(packet + ETHER_HDR_LEN + (ip_header->ip_hl << 2));
                printf("\t┝ TCP Protocol\n");
                if (ntohs(tcp_header->source) == 80 || ntohs(tcp_header->dest) == 80 
                    || ntohs(tcp_header->source) == 443 || ntohs(tcp_header->dest) == 443) {
                    printf("\t┝ HTTP Protocol\n");
                }
                break;

            case IPPROTO_UDP:
                udp_header = (struct udphdr *)(packet + ETHER_HDR_LEN + (ip_header->ip_hl << 2));
                printf("\t┝ UDP Protocol\n");
                break;

            case IPPROTO_ICMP:
                icmp_header = (struct icmphdr *)(packet + ETHER_HDR_LEN + (ip_header->ip_hl << 2));
                printf("\t┝ ICMP Protocol\n");
                break;

            default:
                printf("\t┝ Other Protocol\n");
                break;
        }
    }

    printf("\t┕ Packet Size: %d bytes\n", pkthdr->len);
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    const u_char *packet;
    char *dev;

    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        printf("Device not found: %s\n", errbuf);
        return 1;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("Error opening device %s: %s\n", dev, errbuf);
        return 1;
    }

    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);

    return 0;
}