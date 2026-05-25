#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <pcap.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include "headers.h"

#define ETHERTYPE_IP 0x0800

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_ACK 0x10

#define REDIRECT_MSG \
"HTTP/1.0 302 Redirect\r\n" \
"Location: http://warning.or.kr\r\n" \
"\r\n"

typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t zero;
    uint8_t protocol;
    uint16_t tcp_len;
} pseudo_header;

uint8_t my_mac[6];

int get_mac_address(const char *if_name, uint8_t *mac_out) {
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (fd < 0) {
        perror("socket");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl");
        close(fd);
        return -1;
    }

    memcpy(mac_out, ifr.ifr_hwaddr.sa_data, 6);
    close(fd);

    return 0;
}

uint16_t checksum(uint16_t *buf, int len) {
    uint32_t sum = 0;

    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }

    if (len == 1) {
        sum += *((uint8_t *)buf);
    }

    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return (uint16_t)(~sum);
}

uint16_t tcp_checksum(ip_header *ip, tcp_header *tcp, uint8_t *payload, int payload_len) {
    int tcp_len = sizeof(tcp_header) + payload_len;
    int total_len = sizeof(pseudo_header) + tcp_len;

    uint8_t *buf = calloc(1, total_len);
    if (!buf) {
        perror("calloc");
        exit(1);
    }

    pseudo_header ph;
    ph.src_ip = ip->src_ip;
    ph.dst_ip = ip->dst_ip;
    ph.zero = 0;
    ph.protocol = IPPROTO_TCP;
    ph.tcp_len = htons(tcp_len);

    memcpy(buf, &ph, sizeof(pseudo_header));
    memcpy(buf + sizeof(pseudo_header), tcp, sizeof(tcp_header));

    if (payload_len > 0) {
        memcpy(buf + sizeof(pseudo_header) + sizeof(tcp_header), payload, payload_len);
    }

    uint16_t result = checksum((uint16_t *)buf, total_len);
    free(buf);

    return result;
}

void build_ip_header(ip_header *ip,
                     uint16_t total_len,
                     uint8_t ttl,
                     uint32_t src_ip,
                     uint32_t dst_ip) {
    memset(ip, 0, sizeof(ip_header));

    ip->ver_ihl = 0x45;
    ip->tos = 0;
    ip->tot_len = htons(total_len);
    ip->id = htons(rand() & 0xffff);
    ip->frag_off = 0;
    ip->ttl = ttl;
    ip->protocol = IPPROTO_TCP;
    ip->check = 0;
    ip->src_ip = src_ip;
    ip->dst_ip = dst_ip;

    ip->check = checksum((uint16_t *)ip, sizeof(ip_header));
}

void build_tcp_header(tcp_header *tcp,
                      uint16_t src_port,
                      uint16_t dst_port,
                      uint32_t seq,
                      uint32_t ack,
                      uint8_t flags) {
    memset(tcp, 0, sizeof(tcp_header));

    tcp->src_port = src_port;
    tcp->dst_port = dst_port;
    tcp->seq = seq;
    tcp->ack = ack;
    tcp->offset_reserved = 0x50;
    tcp->flags = flags;
    tcp->window = htons(1024);
    tcp->checksum = 0;
    tcp->urgent = 0;
}

void raw_send(int raw_sock, uint8_t *packet, int packet_len, uint32_t dst_ip) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = dst_ip;

    if (sendto(raw_sock,
               packet,
               packet_len,
               0,
               (struct sockaddr *)&addr,
               sizeof(addr)) < 0) {
        perror("sendto");
    }
}

void send_forward_rst(pcap_t *handle,
                      const uint8_t *org_packet,
                      ip_header *org_ip,
                      tcp_header *org_tcp,
                      int org_payload_len) {
    uint8_t packet[1500];
    memset(packet, 0, sizeof(packet));

    ethernet_header *org_eth = (ethernet_header *)org_packet;

    ethernet_header *eth = (ethernet_header *)packet;
    ip_header *ip = (ip_header *)(packet + sizeof(ethernet_header));
    tcp_header *tcp = (tcp_header *)((uint8_t *)ip + sizeof(ip_header));

    memcpy(eth->src_mac, my_mac, 6);
    memcpy(eth->dst_mac, org_eth->dst_mac, 6);
    eth->ethertype = htons(ETHERTYPE_IP);

    uint16_t ip_total_len = sizeof(ip_header) + sizeof(tcp_header);

    build_ip_header(
        ip,
        ip_total_len,
        org_ip->ttl,
        org_ip->src_ip,
        org_ip->dst_ip
    );

    uint32_t seq = ntohl(org_tcp->seq) + org_payload_len;
    uint32_t ack = ntohl(org_tcp->ack);

    build_tcp_header(
        tcp,
        org_tcp->src_port,
        org_tcp->dst_port,
        htonl(seq),
        htonl(ack),
        TCP_RST | TCP_ACK
    );

    tcp->checksum = tcp_checksum(ip, tcp, NULL, 0);

    int packet_len = sizeof(ethernet_header) + ip_total_len;

    if (pcap_sendpacket(handle, packet, packet_len) != 0) {
        fprintf(stderr, "pcap_sendpacket error: %s\n", pcap_geterr(handle));
    }
}


void send_backward_fin(int raw_sock,
                           ip_header *org_ip,
                           tcp_header *org_tcp,
                           int org_payload_len) {
    uint8_t packet[1500];
    memset(packet, 0, sizeof(packet));

    char redirect[] = REDIRECT_MSG;
    int redirect_len = strlen(redirect);

    ip_header *ip = (ip_header *)packet;
    tcp_header *tcp = (tcp_header *)(packet + sizeof(ip_header));
    uint8_t *payload = packet + sizeof(ip_header) + sizeof(tcp_header);

    memcpy(payload, redirect, redirect_len);

    uint16_t ip_total_len = sizeof(ip_header) + sizeof(tcp_header) + redirect_len;

    build_ip_header(
        ip,
        ip_total_len,
        128,
        org_ip->dst_ip,
        org_ip->src_ip
    );

    uint32_t seq = ntohl(org_tcp->ack);
    uint32_t ack = ntohl(org_tcp->seq) + org_payload_len;

    build_tcp_header(
        tcp,
        org_tcp->dst_port,
        org_tcp->src_port,
        htonl(seq),
        htonl(ack),
        TCP_FIN | TCP_ACK
    );

    tcp->checksum = tcp_checksum(ip, tcp, payload, redirect_len);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = ip->dst_ip;

    if (sendto(raw_sock,
               packet,
               ip_total_len,
               0,
               (struct sockaddr *)&addr,
               sizeof(addr)) < 0) {
        perror("sendto");
    }
}

void usage(char *prog) {
    printf("syntax : %s <interface> <pattern>\n", prog);
    printf("sample : %s eth0 \"Host: test.gilgil.net\"\n", prog);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        usage(argv[0]);
        return -1;
    }

    char *dev = argv[1];
    char *pattern = argv[2];
    int pattern_len = strlen(pattern);
    
    if (get_mac_address(dev, my_mac) < 0) {
        fprintf(stderr, "failed to get MAC address\n");
        return -1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live error: %s\n", errbuf);
        return -1;
    }

    int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_sock < 0) {
        perror("socket");
        pcap_close(handle);
        return -1;
    }

    int opt = 1;
    if (setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        close(raw_sock);
        pcap_close(handle);
        return -1;
    }

    printf("tcp-block start!!\n");
    printf("interface : %s\n", dev);
    printf("pattern   : %s\n", pattern);

    while (1) {
        struct pcap_pkthdr *header;
        const uint8_t *packet;

        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        if (header->caplen < sizeof(ethernet_header) + sizeof(ip_header) + sizeof(tcp_header)) {
            continue;
        }

        ethernet_header *eth = (ethernet_header *)packet;

        if (ntohs(eth->ethertype) != ETHERTYPE_IP) {
            continue;
        }

        ip_header *ip = (ip_header *)(packet + sizeof(ethernet_header));

        int ip_header_len = (ip->ver_ihl & 0x0f) * 4;

        if (ip->protocol != IPPROTO_TCP) {
            continue;
        }

        tcp_header *tcp = (tcp_header *)((uint8_t *)ip + ip_header_len);

        int tcp_header_len = ((tcp->offset_reserved >> 4) & 0x0f) * 4;
        int ip_total_len = ntohs(ip->tot_len);
        int payload_len = ip_total_len - ip_header_len - tcp_header_len;

        if (payload_len <= 0) {
            continue;
        }

        uint8_t *payload = (uint8_t *)tcp + tcp_header_len;

        if (memmem(payload, payload_len, pattern, pattern_len) != NULL) {
            struct in_addr src, dst;
            src.s_addr = ip->src_ip;
            dst.s_addr = ip->dst_ip;

            printf("detected pattern\n");
            printf("    %s:%d -> ",
                   inet_ntoa(src),
                   ntohs(tcp->src_port));

            printf("%s:%d\n",
                   inet_ntoa(dst),
                   ntohs(tcp->dst_port));

            send_forward_rst(handle,packet, ip, tcp, payload_len);
            send_backward_fin(raw_sock, ip, tcp, payload_len);

            printf("forward RST sent\n");
            printf("backward FIN + 302 sent\n");
        }
    }

    close(raw_sock);
    pcap_close(handle);

    return 0;
}
