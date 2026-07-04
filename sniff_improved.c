#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "myheader.h"

void print_mac(const char *label, const u_char *addr)
{
    printf("%s: %02x:%02x:%02x:%02x:%02x:%02x\n",
           label,
           addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

void print_payload(const u_char *payload, int len)
{
    if (len <= 0) {
        printf("   (payload 없음)\n");
        return;
    }

    printf("   [HTTP Message] (%d bytes)\n", len);
    printf("   ----------------------------------------\n   ");
    for (int i = 0; i < len; i++) {
        unsigned char c = payload[i];
        if (c == '\n') {
            printf("\n   ");
        } else if (c == '\r') {
            /* skip */
        } else if (isprint(c)) {
            putchar(c);
        } else {
            putchar('.');
        }
    }
    printf("\n   ----------------------------------------\n");
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
    static int pkt_count = 0;
    pkt_count++;

    printf("\n========== Packet #%d (caplen=%u) ==========\n",
           pkt_count, header->caplen);

    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) != 0x0800) {
        printf("(IPv4 패킷이 아님 - 건너뜀)\n");
        return;
    }

    print_mac("Ethernet Src MAC", eth->ether_shost);
    print_mac("Ethernet Dst MAC", eth->ether_dhost);

    struct ipheader *ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader));

    int ip_header_len = ip->iph_ihl * 4;

    printf("IP Src Address  : %s\n", inet_ntoa(ip->iph_sourceip));
    printf("IP Dst Address  : %s\n", inet_ntoa(ip->iph_destip));
    printf("IP Header Len   : %d bytes\n", ip_header_len);

    if (ip->iph_protocol != IPPROTO_TCP) {
        printf("(TCP 패킷이 아님 - 건너뜀)\n");
        return;
    }

    struct tcpheader *tcp = (struct tcpheader *)
                             (packet + sizeof(struct ethheader) + ip_header_len);

    int tcp_header_len = tcp->th_off * 4;

    printf("TCP Src Port    : %d\n", ntohs(tcp->th_sport));
    printf("TCP Dst Port    : %d\n", ntohs(tcp->th_dport));
    printf("TCP Header Len  : %d bytes\n", tcp_header_len);

    int ethernet_header_len = sizeof(struct ethheader);
    int total_header_len = ethernet_header_len + ip_header_len + tcp_header_len;

    int ip_total_len = ntohs(ip->iph_len);
    int payload_len = ip_total_len - ip_header_len - tcp_header_len;

    const u_char *payload = packet + total_header_len;

    int available = header->caplen - total_header_len;
    if (payload_len > available) payload_len = available;

    print_payload(payload, payload_len);
}

int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev;
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net = 0, mask = 0;

    if (argc == 2) {
        dev = argv[1];
    } else {
        pcap_if_t *alldevs;
        if (pcap_findalldevs(&alldevs, errbuf) == -1) {
            fprintf(stderr, "장치 목록 조회 실패: %s\n", errbuf);
            return 1;
        }
        if (alldevs == NULL) {
            fprintf(stderr, "사용 가능한 네트워크 장치가 없습니다.\n");
            return 1;
        }
        dev = strdup(alldevs->name);
        pcap_freealldevs(alldevs);
    }
    printf("캡처 인터페이스: %s\n", dev);

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "경고: %s (네트워크 정보 없이 계속 진행)\n", errbuf);
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "장치 %s 열기 실패: %s\n", dev, errbuf);
        return 2;
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "이 프로그램은 Ethernet 장치만 지원합니다.\n");
        return 3;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "필터 컴파일 실패(%s): %s\n",
                filter_exp, pcap_geterr(handle));
        return 4;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "필터 적용 실패(%s): %s\n",
                filter_exp, pcap_geterr(handle));
        return 5;
    }

    printf("TCP 패킷 캡처를 시작합니다... (Ctrl+C로 종료)\n");

    pcap_loop(handle, -1, got_packet, NULL);

    pcap_freecode(&fp);
    pcap_close(handle);
    return 0;
}
