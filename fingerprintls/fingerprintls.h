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
#define SNAP_LEN 1522

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Max hostname length */
#define HOST_NAME_MAX 255

#define FPSHARD 32


/* Ethernet addresses are 6 bytes */
// #define ETHER_ADDR_LEN	6

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


/*
  UDP Header
*/
struct udp_header {
    u_int16_t sport;
    u_int16_t dport;
    u_int16_t len;
    u_int16_t check;
};

/*
  Teredo Header
*/
struct teredo_header {
  u_int16_t  part_a;  /* horrible partial byte items, this includes version, class and flow stuff */
  u_int16_t  part_b;   /* In reality this is horrible and wrong, but we ignore this so yolo */
  u_int16_t  length;   /* Payload Length */
  u_int8_t   nxt_header;
  u_int8_t   hop_length;
  struct     in6_addr ip6_src; /* Client IPv4, etc is embedded in here.... nice */
  struct     in6_addr ip6_dst;
};

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
		case 0x301: return "TLSv1.0";
		case 0x302: return "TLSv1.1";
		case 0x303: return "TLSv1.2";
	}
	snprintf(hex, sizeof(hex), "0x%04hx", version);
	return hex;
}

/* Linked list/tree struct.  Used to import the binary blob file exported by fingerprintout.py */
struct fingerprint_new {
  uint16_t  fingerprint_id;
  uint16_t  desc_length;
  char      *desc;
  uint16_t  record_tls_version;
  uint16_t  tls_version;
  uint16_t  ciphersuite_length;
  uint8_t   *ciphersuite;
  uint8_t   compression_length; // Actually *IS* a uint8_t field!!!  ZOMG
  uint8_t   *compression;
  uint16_t  extensions_length;
  uint8_t   *extensions;
  uint16_t  curves_length;
  uint8_t   *curves;
  uint16_t  sig_alg_length;
  uint8_t   *sig_alg;
  uint16_t  ec_point_fmt_length;
  uint8_t   *ec_point_fmt;
  struct    fingerprint_new  *next;
};


/* This works perfectly well for TLS, but does not catch horrible SSLv2 packets, soooooo.... */
//char *default_filter = "tcp[tcp[12]/16*4]=22 and (tcp[tcp[12]/16*4+5]=1) and (tcp[tcp[12]/16*4+9]=3) and (tcp[tcp[12]/16*4+1]=3) and (tcp[tcp[12]/16*4+43]=0)";
/* Filter should now catch TCP based Client Hello, all IPv6 (because BPF doesn't support v6 Payload... gah!) and Client Hellos wrapped in Teredo tunnels */

// XXX CHECK IPv6.... doesn't seem to work properly for Chrome testing time!!
char *default_filter = "(tcp[tcp[12]/16*4]=22 and (tcp[tcp[12]/16*4+5]=1) and (tcp[tcp[12]/16*4+9]=3) and (tcp[tcp[12]/16*4+1]=3)) or (ip6[(ip6[52]/16*4)+40]=22 and (ip6[(ip6[52]/16*4+5)+40]=1) and (ip6[(ip6[52]/16*4+9)+40]=3) and (ip6[(ip6[52]/16*4+1)+40]=3)) or ((udp[14] = 6 and udp[16] = 32 and udp[17] = 1) and ((udp[(udp[60]/16*4)+48]=22) and (udp[(udp[60]/16*4)+53]=1) and (udp[(udp[60]/16*4)+57]=3) and (udp[(udp[60]/16*4)+49]=3))) or (proto 41 and ip[26] = 6 and ip[(ip[72]/16*4)+60]=22 and (ip[(ip[72]/16*4+5)+60]=1) and (ip[(ip[72]/16*4+9)+60]=3) and (ip[(ip[72]/16*4+1)+60]=3))";

//char *default_filter = "";

/* This pushes a bunch of pre-processing out to the BPF filter instead of having to deal with it too much in code */
// Disabled for now becuase it's too noisey... too many false positives
//char *default_filter = "(tcp[tcp[12]/16*4]=22 and (tcp[tcp[12]/16*4+5]=1)) or ((tcp[tcp[12]/16*4+2]=1) and ((tcp[tcp[12]/16*4+3]=3) or (tcp[tcp[12]/16*4+3]=0)))";

/*
  Teredo BPF Notes for this dev branch
*/

/*
  "(udp[14] = 6 and udp[16] = 32 and udp[17] = 1) and ((udp[(udp[60]/16*4)+48]=22) and (udp[(udp[60]/16*4)+53]=1) and (udp[(udp[60]/16*4)+57]=3) and (udp[(udp[60]/16*4)+49]=3))"
  "udp[14] = 6 and udp[16] = 32 and udp[17] = 1" <-- should detect *any* teredo packet.  [14] = 6 captures the next header "6" part.  32 and 1 refer to the 2001::/32 prefix on all Teredo packets.
    XXX BBUUUTTT it only seems to match HTTP over teredo!  Weeeiiirrrdddd


  48 = start of TCP header
  "(udp[(udp[60]/16*4)+48]=22)" <-- is the same as "tcp[tcp[12]/16*4]=22"

  ((udp[(udp[60]/16*4)+48]=22) and (udp[(udp[60]/16*4)+53]=1) and (udp[(udp[60]/16*4)+57]=3) and (udp[(udp[60]/16*4)+49]=3))


  proto 41  <--- all of 6in4
  "proto 41 and ip[26] = 6" <-- tcp header set as next header
  60 for tcp

(ip[ip[72]/16*4]=22 and (ip[ip[72]/16*4+5]=1) and (ip[ip[72]/16*4+9]=3) and (ip[ip[72]/16*4+1]=3))

"proto 41 and ip[26] = 6 and ip[(ip[72]/16*4)+60]=22 and (ip[(ip[72]/16*4+5)+60]=1) and (ip[(ip[72]/16*4+9)+60]=3) and (ip[(ip[72]/16*4+1)+60]=3)" <--- TLS in 6in4  XXX This technique used in IPv6 filter too plz

*/

/* --------- */
/* Externals */
/* --------- */
int newsig_count;
int show_drops;
FILE *json_fd = NULL;
FILE *fpdb_fd = NULL;
FILE *log_fd = NULL;

struct fingerprint_new *search[8][4];
char hostname[HOST_NAME_MAX];			/* store the hostname once to save multiple lookups */


/* These were in main, but this let's the signal handler close as needed */
pcap_t *handle = NULL;						/* packet capture handle */
pcap_dumper_t *output_handle = NULL;					/* output to pcap handle */

struct bpf_program fp;					/* compiled filter program (expression) */
/* --------------------------------------------------------------------- */


// Declare all the functions
int register_signals();
void sig_handler (int signo);
int extensions_compare(uint8_t *packet, uint8_t *fingerprint, int length, int count);
void print_usage(char *bin_name);
void got_packet(u_char *args, const struct pcap_pkthdr *pcap_header, const u_char *packet);
