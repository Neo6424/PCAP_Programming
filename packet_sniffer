#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>

#define ETHERNET_HEADER_SIZE 14
#define ETHER_TYPE_IP 0x0800
#define IP_PROTOCOL_TCP 6

#pragma pack(push, 1)

/* Ethernet header */
struct ethheader {
  u_char  ether_dhost[6]; /* destination host address */
  u_char  ether_shost[6]; /* source host address */
  u_short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address
  struct  in_addr    iph_destip;   //Destination IP address
};

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;               /* source port */
    u_short tcp_dport;               /* destination port */
    u_int   tcp_seq;                 /* sequence number */
    u_int   tcp_ack;                 /* acknowledgement number */
    u_char  tcp_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;                 /* window */
    u_short tcp_sum;                 /* checksum */
    u_short tcp_urp;                 /* urgent pointer */
};

#pragma pack(pop)

// MAC 주소 출력 함수
void print_mac(const u_char *mac) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2],
           mac[3], mac[4], mac[5]);
}

// HTTP 포트인지 확인
int is_http_port(uint16_t port) {
    return port == 80 || port == 8080 || port == 8000;
}

// HTTP 메시지처럼 보이는지 확인
int looks_like_http(const unsigned char *payload, int len) {
    if (len < 4) return 0;

    if (strncmp((const char *)payload, "GET ", 4) == 0) return 1;
    if (len >= 5 && strncmp((const char *)payload, "POST ", 5) == 0) return 1;
    if (len >= 5 && strncmp((const char *)payload, "HEAD ", 5) == 0) return 1;
    if (strncmp((const char *)payload, "PUT ", 4) == 0) return 1;
    if (len >= 7 && strncmp((const char *)payload, "DELETE ", 7) == 0) return 1;
    if (len >= 8 && strncmp((const char *)payload, "OPTIONS ", 8) == 0) return 1;
    if (len >= 6 && strncmp((const char *)payload, "PATCH ", 6) == 0) return 1;
    if (len >= 5 && strncmp((const char *)payload, "HTTP/", 5) == 0) return 1;

    return 0;
}

// HTTP 메시지 출력 함수
void print_http_message(const unsigned char *payload, int len) {
    printf("\n[HTTP Message]\n");

    for (int i = 0; i < len; i++) {
        unsigned char c = payload[i];

        // 출력 가능한 문자, 줄바꿈, 탭 정도만 출력
        if (isprint(c) || c == '\n' || c == '\r' || c == '\t') {
            putchar(c);
        } else {
            putchar('.');
        }
    }

    printf("\n");
}

// 패킷을 잡을 때마다 호출되는 함수
void packet_handler(unsigned char *args,
                    const struct pcap_pkthdr *header,
                    const unsigned char *packet) {
    (void)args;

    // Ethernet Header 크기보다 작으면 무시
    if (header->caplen < ETHERNET_HEADER_SIZE) {
        return;
    }

    struct ethheader *eth =
        (struct ethheader *)packet;

    uint16_t ether_type = ntohs(eth->ether_type);

    // IPv4 패킷이 아니면 무시
    if (ether_type != ETHER_TYPE_IP) {
        return;
    }

    // IP Header 위치
    if (header->caplen < ETHERNET_HEADER_SIZE + sizeof(struct ipheader)) {
        return;
    }

    struct ipheader *ip =
        (struct ipheader *)(packet + ETHERNET_HEADER_SIZE);

    // IP Header 길이 계산
    int ip_header_len = ip->iph_ihl * 4;
    if (ip_header_len < 20) {
        return;
    }

    if (header->caplen < (bpf_u_int32)(ETHERNET_HEADER_SIZE + ip_header_len)) {
        return;
    }

    // IPv4인지 확인
    int ip_version = ip->iph_ver;
    if (ip_version != 4) {
        return;
    }

    // TCP 패킷이 아니면 무시
    if (ip->iph_protocol != IP_PROTOCOL_TCP) {
        return;
    }

    // IP 전체 길이
    int ip_total_len = ntohs(ip->iph_len);
    if (ip_total_len < ip_header_len) {
        return;
    }

    // TCP Header 위치
    if (header->caplen <
        ETHERNET_HEADER_SIZE + ip_header_len + sizeof(struct tcpheader)) {
        return;
    }

    struct tcpheader *tcp =
        (struct tcpheader *)(packet + ETHERNET_HEADER_SIZE + ip_header_len);

    // TCP Header 길이 계산
    int tcp_header_len = TH_OFF(tcp) * 4;
    if (tcp_header_len < 20) {
        return;
    }

    if (header->caplen <
        (bpf_u_int32)(ETHERNET_HEADER_SIZE + ip_header_len + tcp_header_len)) {
        return;
    }

    uint16_t src_port = ntohs(tcp->tcp_sport);
    uint16_t dst_port = ntohs(tcp->tcp_dport);

    // TCP Payload 위치
    int payload_offset =
        ETHERNET_HEADER_SIZE + ip_header_len + tcp_header_len;

    int payload_len =
        ip_total_len - ip_header_len - tcp_header_len;

    if (payload_len < 0) {
        return;
    }

    // 캡처된 길이보다 payload가 길게 계산되면 보정
    if ((int)header->caplen < payload_offset + payload_len) {
        payload_len = header->caplen - payload_offset;
    }

    if (payload_len < 0) {
        payload_len = 0;
    }

    printf("\n========================================\n");

    // Ethernet Header 출력
    printf("[Ethernet Header]\n");
    printf("Source MAC      : ");
    print_mac(eth->ether_shost);
    printf("\n");

    printf("Destination MAC : ");
    print_mac(eth->ether_dhost);
    printf("\n");

    // IP Header 출력
    printf("\n[IP Header]\n");
    printf("Source IP       : %s\n", inet_ntoa(ip->iph_sourceip));
    printf("Destination IP  : %s\n", inet_ntoa(ip->iph_destip));

    // TCP Header 출력
    printf("\n[TCP Header]\n");
    printf("Source Port     : %u\n", src_port);
    printf("Destination Port: %u\n", dst_port);

    // HTTP Message 출력
    if (payload_len > 0) {
        const unsigned char *payload = packet + payload_offset;

        if (is_http_port(src_port) ||
            is_http_port(dst_port) ||
            looks_like_http(payload, payload_len)) {
            print_http_message(payload, payload_len);
        }
    }
}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;

    if (argc != 2) {
        printf("사용법: %s <네트워크 인터페이스>\n", argv[0]);
        printf("예시  : sudo %s eth0\n", argv[0]);
        printf("예시  : sudo %s wlan0\n", argv[0]);
        return 1;
    }

    char *device = argv[1];

    // 네트워크 인터페이스 열기
    handle = pcap_open_live(
        device,     // 네트워크 장치 이름
        BUFSIZ,     // 캡처할 패킷 크기
        1,          // promiscuous mode
        1000,       // timeout
        errbuf
    );

    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live() 실패: %s\n", errbuf);
        return 1;
    }

    // HTTP 평문 패킷만 캡처
    char filter_exp[] = "tcp port 80";

    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "pcap_compile() 실패\n");
        pcap_close(handle);
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "pcap_setfilter() 실패\n");
        pcap_freecode(&fp);
        pcap_close(handle);
        return 1;
    }

    printf("패킷 캡처 시작...\n");
    printf("사용 인터페이스: %s\n", device);
    printf("캡처 필터: %s\n", filter_exp);
    printf("종료하려면 Ctrl + C\n");

    // 패킷 캡처 반복
    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_freecode(&fp);
    pcap_close(handle);

    return 0;
}
