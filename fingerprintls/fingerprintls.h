/*
Exciting Licence Info.....

This file is part of FingerprinTLS.

FingerprinTLS is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

FingerprinTLS is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Foobar.  If not, see <http://www.gnu.org/licenses/>.

Exciting Licence Info Addendum.....

FingerprinTLS is additionally released under the "don't judge me" program
whereby it is forbidden to rip into me too harshly for programming
mistakes, kthnxbai.

*/

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
//#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IPv4 header */
struct ipv4_header {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct tcp_header {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        #if BYTE_ORDER == LITTLE_ENDIAN
                u_int   th_x2:4,                /* (unused) */
                        th_off:4;               /* data offset */
        #endif
        #if BYTE_ORDER == BIG_ENDIAN
                u_int   th_off:4,               /* data offset */
                        th_x2:4;                /* (unused) */
        #endif
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

#define SSL_MIN_GOOD_VERSION	0x002
#define SSL_MAX_GOOD_VERSION	0x304

#define OFFSET_HELLO_VERSION	9
#define OFFSET_SESSION_LENGTH	43
#define OFFSET_CIPHER_LIST	44

#define SSLV2_OFFSET_HELLO_VERSION	3
#define SSLV2_OFFSET_SESSION_LENGTH	6
#define SSLV2_OFFSET_CIPHER_LIST	44


char* ssl_version(u_short version) {
	static char hex[7];
	switch (version) {
		case 0x002: return "SSLv2";
		case 0x300: return "SSLv3";
		case 0x301: return "TLSv1";
		case 0x302: return "TLSv1.1";
		case 0x303: return "TLSv1.2";
	}
	snprintf(hex, sizeof(hex), "0x%04hx", version);
	return hex;
}
/* This works perfectly well for TLS, but does not catch horrible SSLv2 packets, soooooo.... */
//char *default_filter = "tcp[tcp[12]/16*4]=22 and (tcp[tcp[12]/16*4+5]=1) and (tcp[tcp[12]/16*4+9]=3) and (tcp[tcp[12]/16*4+1]=3) and (tcp[tcp[12]/16*4+43]=0)";
char *default_filter = "(tcp[tcp[12]/16*4]=22 and (tcp[tcp[12]/16*4+5]=1) and (tcp[tcp[12]/16*4+9]=3) and (tcp[tcp[12]/16*4+1]=3)) or (ip6 and tcp)";

/* This pushes a bunch of pre-processing out to the BPF filter instead of having to deal with it too much in code */
// Disabled for now becuase it's too noisey... too many false positives
//char *default_filter = "(tcp[tcp[12]/16*4]=22 and (tcp[tcp[12]/16*4+5]=1)) or ((tcp[tcp[12]/16*4+2]=1) and ((tcp[tcp[12]/16*4+3]=3) or (tcp[tcp[12]/16*4+3]=0)))";
