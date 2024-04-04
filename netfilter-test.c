#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>        /* for NF_ACCEPT */
#include <errno.h>
#include <regex.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#define HOST_PATTERN_LEN 6 

unsigned char host_pattern[HOST_PATTERN_LEN] = {0x48, 0x6f, 0x73, 0x74, 0x3a, 0x20};

void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i != 0 && i % 16 == 0)
            printf("\n");
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

static void print_host_address(const unsigned char *payload, int payload_len) {
    unsigned char host_addr[256] = {0}; 
    int host_addr_len = 0;
    for (int i = 0; i <= payload_len - HOST_PATTERN_LEN; i++) {
        if (memcmp(payload + i, host_pattern, HOST_PATTERN_LEN) == 0) {
            i += HOST_PATTERN_LEN;
            while (payload[i] != '\r' && (i < payload_len) && host_addr_len < sizeof(host_addr) - 1) {
                host_addr[host_addr_len++] = payload[i++];
            }
            if (host_addr_len > 0) {
                printf("Host Address: ");
                dump(host_addr, host_addr_len);
            }
            break;
        }
    }
}

static u_int32_t print_pkt(struct nfq_q_handle *qh, struct nfq_data *tb, const char* target_host) {
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark, ifi;
    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ", ntohs(ph->hw_protocol), ph->hook, id);
    } else {
        return 0;
    }

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);

        printf("hw_src_addr=");
        for (i = 0; i < hlen - 1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen - 1]);
    }

    mark = nfq_get_nfmark(tb);
    if (mark)
        printf("mark=%u ", mark);

    ifi = nfq_get_indev(tb);
    if (ifi)
        printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi)
        printf("outdev=%u ", ifi);
    ifi = nfq_get_physindev(tb);
    if (ifi)
        printf("physindev=%u ", ifi);

    ifi = nfq_get_physoutdev(tb);
    if (ifi)
        printf("physoutdev=%u ", ifi);

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0)
        printf("payload_len=%d\n", ret);

    if (ret >= 0 && data[9] == IPPROTO_TCP) {
        int ip_hdr_len = (data[0] & 0x0F) * 4;
        unsigned char *tcp_header = data + ip_hdr_len;
        int tcp_hdr_len = ((tcp_header[12] >> 4) & 0x0F) * 4;
        unsigned char *payload = tcp_header + tcp_hdr_len;
        int payload_len = ret - ip_hdr_len - tcp_hdr_len;

        print_host_address(payload, payload_len);

        regex_t regex;
        regmatch_t pmatch[2]; //? 여기서부터
        char pattern[256];

        snprintf(pattern, sizeof(pattern), "Host: %s\r\n", target_host);

        if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
            fprintf(stderr, "Could not compile regex\n");
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
        }

        if (regexec(&regex, (const char*)payload, 2, pmatch, 0) == 0) {
            printf("Dropping packet to %s\n", target_host);
            regfree(&regex);
            return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
        } else {
            regfree(&regex); //이게 진짜
        }
    }
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
   const char* target_host = (const char*)data; //와..이건좀..
    printf("entering callback\n");
    return print_pkt(qh, nfa, target_host);
}

int main(int argc, char **argv) {
	if (argc != 2) {
        fprintf(stderr, "Usage: %s <host>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *target_host = argv[1];
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    char buf[4096] __attribute__ ((aligned));

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    qh = nfq_create_queue(h, 0, &cb, (void*)target_host); //미친 2
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    while (1) {
        int rv = recv(fd, buf, sizeof(buf), 0);
        if (rv >= 0) {
            nfq_handle_packet(h, buf, rv);
            continue;
        }

        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    nfq_destroy_queue(qh);
    nfq_close(h);

    return 0;
}

