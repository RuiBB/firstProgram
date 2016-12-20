#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define SNAP_LEN 1518

#define SIZE_ETHERNET 14

#define ETHER_ADDR_LEN    6

/* Ethernet header */
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
    u_char ip_vhl; /* version << 4 | header length >> 2 */
    u_char ip_tos; /* type of service */
    u_short ip_len; /* total length */
    u_short ip_id; /* identification */
    u_short ip_off; /* fragment offset field */
    #define IP_RF 0x8000 /* reserved fragment flag */
    #define IP_DF 0x4000 /* dont fragment flag */
    #define IP_MF 0x2000 /* more fragments flag */
    #define IP_OFFMASK 0x1fff /* mask for fragmenting bits */
    u_char ip_ttl; /* time to live */
    u_char ip_p; /* protocol */
    u_short ip_sum; /* checksum */
    struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport; /* source port */
    u_short th_dport; /* destination port */
    tcp_seq th_seq; /* sequence number */
    tcp_seq th_ack; /* acknowledgement number */
    u_char th_offx2; /* data offset, rsvd */
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
    #define TH_FIN 0x01
    #define TH_SYN 0x02
    #define TH_RST 0x04
    #define TH_PUSH 0x08
    #define TH_ACK 0x10
    #define TH_URG 0x20
    #define TH_ECE 0x40
    #define TH_CWR 0x80
    #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win; /* window */
    u_short th_sum; /* checksum */
    u_short th_urp; /* urgent pointer */
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void print_payload(const u_char *payload, int len);

void print_hex_ascii_line(const u_char *payload, int len, int offset);


void print_hex_ascii_line(const u_char *payload, int len, int offset)
{

    int i;
    int gap;
    const u_char *ch;
    printf("%05d ", offset);
    ch = payload;
    for(i = 0; i < len; i++) {
        printf("%02x ", *ch);
        ch++;
        if (i == 7)
            printf(" ");
    }
    if (len < 8)
        printf(" ");
    if (len < 16) {
        gap = 16 - len;
        for (i = 0; i < gap; i++) {
            printf(" ");
        }
    }
    printf(" ");
    ch = payload;
    for(i = 0; i < len; i++) {
        if (isprint(*ch))
            printf("%c", *ch);
        else
            printf(".");
        ch++;
    }

    printf("\n");

return;
}

void print_payload(const u_char *payload, int len)
{

    int len_rem = len;
    int line_width = 16;
    int line_len;
    int offset = 0;
    const u_char *ch = payload;

    if (len <= 0)
        return;

    /* data fits on one line */
    if (len <= line_width) {
        print_hex_ascii_line(ch, len, offset);
        return;
    }

    /* data spans multiple lines */
    for ( ;; ) {
        /* compute current line length */
        line_len = line_width % len_rem;
        /* print line */
        print_hex_ascii_line(ch, line_len, offset);
        /* compute total remaining */
        len_rem = len_rem - line_len;
        /* shift pointer to remaining bytes to print */
        ch = ch + line_len;
        /* add offset */
        offset = offset + line_width;
        /* check if we have line width chars or less */
        if (len_rem <= line_width) {
            /* print last line and get out */
            print_hex_ascii_line(ch, len_rem, offset);
            break;
        }
    }
return;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    static int count = 1;
    const struct sniff_ethernet *ethernet;
    const struct sniff_ip *ip;
    const struct sniff_tcp *tcp;
    const u_char *payload;
    int size_ip;
    int size_tcp;
    int size_payload;
    printf("\nPacket number %d:\n", count);
    count++;
    ethernet = (struct sniff_ethernet*)(packet);

    printf(" From MAC:%X.%X.%X.%X.%X.%X\n",  ethernet->ether_shost[0],
                                            ethernet->ether_shost[1],
                                            ethernet->ether_shost[2],
                                            ethernet->ether_shost[3],
                                            ethernet->ether_shost[4],
                                            ethernet->ether_shost[5]);
    printf(" To MAC:%X.%X.%X.%X.%X.%X\n",    ethernet->ether_dhost[0],
                                            ethernet->ether_dhost[1],
                                            ethernet->ether_dhost[2],
                                            ethernet->ether_dhost[3],
                                            ethernet->ether_dhost[4],
                                            ethernet->ether_dhost[5]);
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    printf(" From: %s\n", inet_ntoa(ip->ip_src));
    printf(" To: %s\n", inet_ntoa(ip->ip_dst));
    switch(ip->ip_p) {
        case IPPROTO_TCP:
            printf(" Protocol: TCP\n");
            break;
        case IPPROTO_UDP:
            printf(" Protocol: UDP\n");
            return;
        case IPPROTO_ICMP:
            printf(" Protocol: ICMP\n");
            return;
        case IPPROTO_IP:
            printf(" Protocol: IP\n");
            return;
        default:
            printf(" Protocol: unknown\n");
            return;
    }
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    printf(" Src port: %d\n", ntohs(tcp->th_sport));
    printf(" Dst port: %d\n", ntohs(tcp->th_dport));
    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

    size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

    if (size_payload > 0) {
        printf(" Payload (%d bytes):\n", size_payload);
        print_payload(payload, size_payload);
    }

return;
}

int main(int argc, char **argv)
{

    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    char filter_exp[] = "tcp";
    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    int num_packets = -1;
    dev=pcap_lookupdev(errbuf);
    pcap_lookupnet(dev, &net, &mask, errbuf);
    printf("Device: %s\n", dev);
    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);
    pcap_loop(handle, num_packets, got_packet, NULL);
    pcap_freecode(&fp);
    pcap_close(handle);
    return 0;
}