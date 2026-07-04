#ifndef __MY_HEADER_H__
#define __MY_HEADER_H__

#include <netinet/in.h>

#define ETHER_ADDR_LEN 6

/* Ethernet Header (14 bytes) */
struct ethheader {
    u_char  ether_dhost[ETHER_ADDR_LEN];
    u_char  ether_shost[ETHER_ADDR_LEN];
    u_short ether_type;
};

/* IP Header */
struct ipheader {
    unsigned char      iph_ihl:4,
                        iph_ver:4;
    unsigned char      iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned short int iph_flag:3,
                        iph_offset:13;
    unsigned char      iph_ttl;
    unsigned char      iph_protocol;
    unsigned short int iph_chksum;
    struct  in_addr    iph_sourceip;
    struct  in_addr    iph_destip;
};

/* TCP Header */
struct tcpheader {
    unsigned short int th_sport;
    unsigned short int th_dport;
    unsigned int       th_seq;
    unsigned int       th_ack;
    unsigned char      th_x2:4,
                        th_off:4;
    unsigned char      th_flags;
    unsigned short int th_win;
    unsigned short int th_sum;
    unsigned short int th_urp;
};

#endif
