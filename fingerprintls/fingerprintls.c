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
// TODO

// XXX IPv6 (This should be trivial I just haven't had the time... or ipv6 addresses)
// XXX add some indexing stuff to fingerprint database instead of searching array in order

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
#include <unistd.h>
#include <net/ethernet.h>
#include <netinet/ip6.h>

/* My own header sherbizzle */
#include "fingerprintls.h"

/* Statically compiled Fingerprint DB (sorryNotSorry) */
#include "fpdb.h"

/* Binary compare *first with *second for length bytes */
int binary_compare(uint8_t *first, uint8_t *second, int length) {
		int x;
		/* Non-existant field needs to be dealt with before counting fun */
		/* We have already checked that lengths match */
		if (length == 0) {
			return 1;
		}

		for(x = 0 ; x < length ; x++) {
			if(*first != *second) {
				break;
			} else {
				first++;
				second++;
			}
		}
		if (x == length) {
			return 1;
		} else {
			return 0;
		}
}

/* Compare extensions in packet *packet with fingerprint *fingerprint */
int extensions_compare(uint8_t *packet, uint8_t *fingerprint, int length, int count) {
	/* XXX check that all things passed to this _are_ uint8_t and we're not only partially checking stuff that may be longer!!!! */
	int x = 0;
	int y = 0;
	int retval = 1;
	for (; x < length ;) {
		if (((uint8_t) packet[x] != fingerprint[y] ) || ((uint8_t) packet[x+1] != fingerprint[y+1])) {
			retval = 0;
			break;
		} else {
			y += 2;
			x = x + 4 + (packet[(x+2)]*256) + (packet[x+3]);
		}
	}
	return retval;
}


int newsig_count;
int show_drops;
FILE *json_fd;

/*
 * print help text
 */
void print_usage(char *bin_name) {
	fprintf(stderr, "Usage: %s <options>\n\n", bin_name);
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "    -h                This message\n");
	fprintf(stderr, "    -i <interface>    Sniff packets from specified interface\n");
	fprintf(stderr, "    -p <pcap file>    Read packets from specified pcap file\n");
	fprintf(stderr, "    -j <json file>    Output JSON fingerprints\n");
	fprintf(stderr, "    -s                Output JSON signatures of unknown connections to stdout\n");
	fprintf(stderr, "    -d                Show reasons for discarded packets (post BPF)\n");
	fprintf(stderr, "    -u <uid>          Drop privileges to specified UID (not username)  ** BETA, use at your own peril! **\n");
	fprintf(stderr, "\n");
	return;
}

void output() {

}

/*
 * dissect/print/do/thing recieved packets
 */
void got_packet(u_char *args, const struct pcap_pkthdr *pcap_header, const u_char *packet) {

	/* ************************************************************************* */
	/* Variables, gotta have variables, and structs and pointers....  and things */
	/* ************************************************************************* */

	extern FILE *json_fd, *struct_fd;
	extern int newsig_count;

	int size_ip = 0;
	int size_tcp;
	int size_payload;
	int size_vlan_offset=0;

	int ip_version=0;
	int af_type;
	char src_address_buffer[64];
	char dst_address_buffer[64];

	/* pointers to key places in the packet headers */
	const struct ether_header *ethernet;	/* The ethernet header [1] */
	const struct ipv4_header *ipv4;         /* The IPv4 header */
	const struct ip6_hdr *ipv6;             /* The IPv6 header */
	const struct tcp_header *tcp;           /* The TCP header */
	const u_char *payload;                  /* Packet payload */

	/* Different to struct fingerprint in fpdb.h, this is for building new fingerprints */
	struct tmp_fingerprint {
		int 	id;
		char 	desc[128];
		uint16_t record_tls_version;
		uint16_t tls_version;
		int 	ciphersuite_length;
		uint8_t	*ciphersuite;
		int 	compression_length;
		uint8_t	*compression;
		int 	extensions_length;
		uint8_t	*extensions;
		int		e_curves_length;
		uint8_t	*e_curves;
		int sig_alg_length;
		uint8_t	*sig_alg;
		int ec_point_fmt_length;
		uint8_t	*ec_point_fmt;
		char 	*server_name;
	} packet_fp;


	/* ******************************************** */
	/* Set pointers to the main parts of the packet */
	/* ******************************************** */

	while(ip_version==0){
		/* Ethernet Frame */
		/* CAREFUL: This will obliterate the src/dst MAC pointers. */
		ethernet = (struct ether_header*)(packet+size_vlan_offset);

		/* Determine the ethernet frame type, and handle accordingly */
		switch(ntohs(ethernet->ether_type)){
			case ETHERTYPE_VLAN:
				size_vlan_offset+=4;
				/* This will loop through to handle nested 802.1Q headers */
				break;
			case ETHERTYPE_IP:
				/* IPv4 */
				ip_version=4;
				af_type=AF_INET;
				break;
			case ETHERTYPE_IPV6:
				/* IPv6 */
				ip_version=6;
				af_type=AF_INET6;
				break;
			default:
				/* Something's gone wrong... Doesn't appear to be a valid ethernet frame? */
				if (show_drops)
					fprintf(stderr, "Malformed Ethernet frame\n");
				return;
		}
	}
	if (ip_version==4){
		/* IP Header */
		ipv4 = (struct ipv4_header*)(packet + SIZE_ETHERNET + size_vlan_offset);
		size_ip = IP_HL(ipv4)*4;

		if (size_ip < 20) {
			/* This is just wrong, not even bothering */
			if(show_drops)
				fprintf(stderr, "Packet Drop: Invalid IP header length: %u bytes\n", size_ip);
			return;
		}

		/* TCP Header */
		if (ipv4->ip_p != IPPROTO_TCP) {
			/* Not TCP, not trying.... don't care.  The BPF filter should
			 * prevent this happening, but if I remove it you can guarantee I'll have
			 * forgotten an edge case :) */
			 if (show_drops)
			 	fprintf(stderr, "Packet Drop: non-TCP made it though the filter... weird\n");
			return;
		}
	}
	else if(ip_version==6){
		/* IP Header */
		ipv6 = (struct ip6_hdr*)(packet + SIZE_ETHERNET + size_vlan_offset);
		size_ip = 40;

		/* TODO: Parse 'next header(s)' */
		//printf("IP Version? %i\n",ntohl(ipv6->ip6_vfc)>>28);
		//printf("Traffic Class? %i\n",(ntohl(ipv6->ip6_vfc)&0x0ff00000)>>24);
		//printf("Flow Label? %i\n",ntohl(ipv6->ip6_vfc)&0xfffff);
		//printf("Payload? %i\n",ntohs(ipv6->ip6_plen));
		//printf("Next Header? %i\n",ipv6->ip6_nxt);

		/* Sanity Check... Should be IPv6 */
		if ((ntohl(ipv6->ip6_vfc)>>28)!=6){
			if(show_drops)
				fprintf(stderr, "Packet Drop: Invalid IPv6 header\n");
			return;
		}

		switch(ipv6->ip6_nxt){
			case 6:		/* TCP */
				break;
			case 17:	/* UDP */
			case 58:	/* ICMPv6 */
				if(show_drops)
				 	fprintf(stderr, "Packet Drop: non-TCP made it though the filter... weird\n");
				return;

			default:
				printf("Packet Drop: Unhandled IPv6 next header: %i\n",ipv6->ip6_nxt);
				return;
		}
	}

	/* Yay, it's TCP, let's set the pointer */
	tcp = (struct tcp_header*)(packet + SIZE_ETHERNET + size_vlan_offset + size_ip);

	size_tcp = (tcp->th_off * 4);
	if (size_tcp < 20) {
		/* Not even trying if this is the case.... kthnxbai */
		if(show_drops)
			printf("Packet Drop: Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}

	/* Packet Payload */

	/* Set the payload pointer */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_vlan_offset + size_ip + (tcp->th_off * 4));

	/* ------------------------------------ */

	/* How big is our payload, according to header info ??? */
	size_payload = (pcap_header->len - SIZE_ETHERNET - size_vlan_offset - size_ip - (tcp->th_off * 4));
	/* ---------------------------------------------------- */


	/* ******************************************************** */
	/* Some basic checks, ignore the packet if it vaguely fails */
	/* ******************************************************** */

	/* Check it's actually a valid TLS version - this seems to prevent most false positives */
	switch ((payload[OFFSET_HELLO_VERSION]*256) + payload[OFFSET_HELLO_VERSION+1]) {
		/* Valid TLS Versions */
		/* Yeah - SSLv2 isn't formatted this way, what a PITA! */
		//case 0x002:	/* SSLv2 */
		case 0x300:	/* SSLv3 */
		case 0x301:	/* TLSv1 */
		case 0x302:	/* TLSv1.1 */
		case 0x303:	/* TLSv1.2 */
			break;
		default:
			/* Doesn't look like a valid TLS version.... probably not even a TLS packet, if it is, it's a bad one */
			if(show_drops)
				printf("Packet Drop: Bad TLS Version\n");
				//printf("%X %X %X %X\n",payload[OFFSET_HELLO_VERSION-8],payload[OFFSET_HELLO_VERSION-7],payload[OFFSET_HELLO_VERSION-6],payload[OFFSET_HELLO_VERSION-5]);
				//printf("%X %X %X %X\n",payload[OFFSET_HELLO_VERSION-4],payload[OFFSET_HELLO_VERSION-3],payload[OFFSET_HELLO_VERSION-2],payload[OFFSET_HELLO_VERSION-1]);
				//printf("%X %X %X %X\n",payload[OFFSET_HELLO_VERSION],payload[OFFSET_HELLO_VERSION+1],payload[OFFSET_HELLO_VERSION+2],payload[OFFSET_HELLO_VERSION+3]);
				//printf("%X %X %X %X\n",payload[OFFSET_HELLO_VERSION+4],payload[OFFSET_HELLO_VERSION+5],payload[OFFSET_HELLO_VERSION+6],payload[OFFSET_HELLO_VERSION+7]);
				//printf("%X %X %X %X\n",payload[OFFSET_HELLO_VERSION+8],payload[OFFSET_HELLO_VERSION+9],payload[OFFSET_HELLO_VERSION+10],payload[OFFSET_HELLO_VERSION+11]);
			return;
	}

	/* Check the size of the sessionid */
	const u_char *cipher_data = &payload[OFFSET_SESSION_LENGTH];
	if (size_payload < OFFSET_SESSION_LENGTH + cipher_data[0] + 3) {
		if(show_drops)
			printf("Packet Drop: Session ID looks bad\n");
		return;
	}


	/* ************************************************************************ */
	/* The bit that grabs the useful info from packets (or sets pointers to it) */
	/* ************************************************************************ */

	/* ID and Desc (with defaults for unknown fingerprints) */
	packet_fp.id = 0;
	if (ip_version==4) {
		inet_ntop(af_type,(void*)&ipv4->ip_src,src_address_buffer,sizeof(src_address_buffer));
		inet_ntop(af_type,(void*)&ipv4->ip_dst,dst_address_buffer,sizeof(dst_address_buffer));
	}
	else if (ip_version==6) {
		inet_ntop(af_type,(void*)&ipv6->ip6_src,src_address_buffer,sizeof(src_address_buffer));
		inet_ntop(af_type,(void*)&ipv6->ip6_dst,dst_address_buffer,sizeof(dst_address_buffer));
	}

	snprintf(packet_fp.desc,sizeof(packet_fp.desc),"Unknown: %s:%i -> %s:%i", src_address_buffer, ntohs(tcp->th_sport), dst_address_buffer, ntohs(tcp->th_dport));

	/* TLS Version (Record Layer - not proper proper) */
	packet_fp.record_tls_version = (payload[1]*256) + payload[2];

	/* TLS Version */
	packet_fp.tls_version = (payload[OFFSET_HELLO_VERSION]*256) + payload[OFFSET_HELLO_VERSION+1];

	/* CipherSuite */
	cipher_data += 1 + cipher_data[0];
	u_short cs_len = cipher_data[0]*256 + cipher_data[1];

	/* Length */
	packet_fp.ciphersuite_length = (cipher_data[0]*256) + cipher_data[1];


	/* CipherSuites */
	cipher_data += 2; // skip cipher suites length
	packet_fp.ciphersuite = (uint8_t *)cipher_data;

	/* Compression */
	u_short comp_len = cipher_data[cs_len];

	/* Length */
	packet_fp.compression_length = comp_len;

	/* Compression List */
	cipher_data += cs_len + 1;
	packet_fp.compression = (uint8_t *)cipher_data;

	/* Extensions */
	u_short ext_len = cipher_data[comp_len]*256 + cipher_data[comp_len+1];
	int ext_id, ext_count = 0;

	/* Length */
	cipher_data += comp_len + 2;

	packet_fp.e_curves = NULL;
	packet_fp.sig_alg = NULL;
	packet_fp.ec_point_fmt = NULL;
	packet_fp.server_name = NULL;


	/* So this works - so overall length seems ok */
	packet_fp.extensions = (uint8_t *)cipher_data;

	/* If we are at the end of the packet we have no extensions, without this
		 we will just run off the end of the packet into unallocated space :/
	*/
	if(cipher_data - payload > size_payload) {
		ext_len = 0;
	}

	/* Loop through the extensions */
	for (ext_id = 0; ext_id < ext_len ; ext_id++ ) {
		int ext_type;

		/* Set the extension type */
		ext_type = (cipher_data[ext_id]*256) + cipher_data[ext_id + 1];
		ext_count++;

		/* Handle some special cases */
		switch(ext_type) {
			case 0x000a:
				/* elliptic_curves */
				packet_fp.e_curves = (uint8_t *)&cipher_data[ext_id + 2];
				/* 2 & 3, not 0 & 1 because of 2nd length field */
				packet_fp.e_curves_length = packet_fp.e_curves[2]*256 + packet_fp.e_curves[3];
				break;
			case 0x000b:
				/* ec_point formats */
				packet_fp.ec_point_fmt = (uint8_t *)&cipher_data[ext_id + 2];
				packet_fp.ec_point_fmt_length = packet_fp.ec_point_fmt[2];
				break;
			case 0x000d:
				/* Signature algorithms */
				packet_fp.sig_alg = (uint8_t *)&cipher_data[ext_id + 2];
				packet_fp.sig_alg_length = packet_fp.sig_alg[2]*256 + packet_fp.sig_alg[3];
				break;
			case 0x0000:
				/* Definitely *NOT* signature-worthy
				 * but worth noting for debugging source
				 * of packets during signature creation.
				 */
				/* Server Name */
				packet_fp.server_name = (char *)&cipher_data[ext_id+2];
				break;
			case 0x0015:
				/* Padding...  Causes 2 signatures to be needed because it sometimes appears and sometimes not */

				break;
		}


		/* Increment past the payload of the extensions */
		ext_id += (cipher_data[ext_id + 2]*256) + cipher_data[ext_id + 3] + 3;

	}


	/* ********************************************* */
	/* The "compare to the fingerprint database" bit */
	/* ********************************************* */
	int fp_loop, arse;

	/* XXX This horrible kludge to get around the 2 length fields.  FIX IT! */
	uint8_t *realcurves = packet_fp.e_curves;
	if (packet_fp.e_curves != NULL) {
		realcurves += 4;
	} else {
		realcurves = NULL;
		packet_fp.e_curves_length = 0;
	}
		/* ******************************************************************** */

	/* XXX This horrible kludge to get around the 2 length fields.  FIX IT! */
	uint8_t *realsig_alg = packet_fp.sig_alg;
		if(packet_fp.sig_alg != NULL) {
		realsig_alg += 4;
	} else {
		realsig_alg = NULL;
		packet_fp.sig_alg_length = 0;
	}
	/* ******************************************************************** */

	/* XXX This horrible kludge to get around the 2 length fields.  FIX IT! */
	uint8_t *realec_point_fmt = packet_fp.ec_point_fmt;
	if(packet_fp.ec_point_fmt != NULL) {
		realec_point_fmt += 3;
	} else {
		realec_point_fmt = NULL;
		packet_fp.ec_point_fmt_length = 0;
	}
	/* ******************************************************************** */

	int matchcount = 0;
	/* XXX Should order these to hit easy differentiators first */
	for(fp_loop = 0; fp_loop < (sizeof(fpdb)/sizeof(fpdb[0])); fp_loop++) {

		if ((packet_fp.record_tls_version == fpdb[fp_loop].record_tls_version) &&
			(packet_fp.tls_version == fpdb[fp_loop].tls_version) &&

/* XXX extensions_length is misleading!  Length is variable, it is a count of
   uint8_t's that makes the extensions _list_.  Furthermore, these values are
	 in pairs, so the count is actually half this....  Handle much more carefully
	 kthnxbai */

				/* Note: check lengths match first, the later comparisons assume these already match */
				(packet_fp.ciphersuite_length == fpdb[fp_loop].ciphersuite_length) &&
				(packet_fp.compression_length == fpdb[fp_loop].compression_length) &&
				((ext_count * 2) == fpdb[fp_loop].extensions_length) &&
				(packet_fp.e_curves_length == fpdb[fp_loop].e_curves_length) &&
				(packet_fp.sig_alg_length == fpdb[fp_loop].sig_alg_length) &&
				(packet_fp.ec_point_fmt_length == fpdb[fp_loop].ec_point_fmt_length) &&

				binary_compare(packet_fp.ciphersuite, fpdb[fp_loop].ciphersuite, fpdb[fp_loop].ciphersuite_length) &&
				binary_compare(packet_fp.compression, fpdb[fp_loop].compression, fpdb[fp_loop].compression_length) &&
				extensions_compare(packet_fp.extensions, fpdb[fp_loop].extensions, ext_len, fpdb[fp_loop].extensions_length) &&
				binary_compare(realcurves, fpdb[fp_loop].e_curves, fpdb[fp_loop].e_curves_length) &&
				binary_compare(realsig_alg, fpdb[fp_loop].sig_alg, fpdb[fp_loop].sig_alg_length) &&
				binary_compare(realec_point_fmt, fpdb[fp_loop].ec_point_fmt, fpdb[fp_loop].ec_point_fmt_length)) {

				/* Whole criteria match.... woo! */
				matchcount++;
				printf("Fingerprint Matched: \"%s\" %s connection from %s:%i to ", fpdb[fp_loop].desc, ssl_version(packet_fp.tls_version),
					src_address_buffer, ntohs(tcp->th_sport));
				printf("%s:%i ", dst_address_buffer, ntohs(tcp->th_dport));
				printf("Servername: \"");
				if(packet_fp.server_name != NULL) {
					for (arse = 7 ; arse <= (packet_fp.server_name[0]*256 + packet_fp.server_name[1]) + 1 ; arse++) {
						if (packet_fp.server_name[arse] > 0x20 && packet_fp.server_name[arse] < 0x7b)
							printf("%c", packet_fp.server_name[arse]);
					}
				} else {
					printf("Not Set");
				}
				printf("\"");

				if(matchcount > 1)
					/* This shouldn't happen, but is useful to debug duplicate fingerprints */

					/* May disable this for speed optimisation (or make it configurable) */

					printf("(Multiple Match)");
				printf("\n");

			} else {
				/* The 'if' failed, so we may wish to do something fuzzy here */

			}

	}


	/* ********************************************* */


	if(matchcount == 0) {

		newsig_count++;

		fprintf(json_fd, "{\"id\": %i, \"desc\": \"%s\", ", packet_fp.id, packet_fp.desc);
		fprintf(json_fd, "\"record_tls_version\": \"0x%.04X\", ", packet_fp.record_tls_version);
		fprintf(json_fd, "\"tls_version\": \"0x%.04X\", \"ciphersuite_length\": \"0x%.04X\", ",
			packet_fp.tls_version, packet_fp.ciphersuite_length);

		fprintf(json_fd, "\"ciphersuite\": \"");
		for (arse = 0; arse < packet_fp.ciphersuite_length; ) {
			fprintf(json_fd, "0x%.02X%.02X", (uint8_t) packet_fp.ciphersuite[arse], (uint8_t) packet_fp.ciphersuite[arse+1]);
			arse = arse + 2;
			if(arse + 1 < packet_fp.ciphersuite_length)
				fprintf(json_fd, " ");
		}
		fprintf(json_fd, "\", ");



		fprintf(json_fd, "\"compression_length\": \"%i\", ",
			packet_fp.compression_length);

		fprintf(json_fd, " \"compression\": \"");
		if (packet_fp.compression_length == 1) {
			fprintf(json_fd, "0x%.02X", (uint8_t) packet_fp.compression[0]);
		} else {
			for (arse = 0; arse < packet_fp.compression_length; ) {
				fprintf(json_fd, "0x%.02X", (uint8_t) packet_fp.compression[arse]);
				arse++;
				if(arse < packet_fp.compression_length)
					fprintf(json_fd, " ");
			}
		}

		fprintf(json_fd, "\", ");


		fprintf(json_fd, "\"extensions\": \"");
		for (arse = 0 ; arse < ext_len ;) {
			fprintf(json_fd, "0x%.02X%.02X", (uint8_t) packet_fp.extensions[arse], (uint8_t) packet_fp.extensions[arse+1]);
			arse = arse + 4 + (packet_fp.extensions[(arse+2)]*256) + (packet_fp.extensions[arse+3]);
			if(arse < ext_len -1)
				fprintf(json_fd, " ");
		}
		fprintf(json_fd, "\"");

		if(packet_fp.e_curves != NULL) {
			fprintf(json_fd, ", \"e_curves\": \"");

			for (arse = 4 ; arse <= (packet_fp.e_curves[0]*256 + packet_fp.e_curves[1]) &&
				(packet_fp.e_curves[0]*256 + packet_fp.e_curves[1]) > 4 ; arse = arse + 2) {

				fprintf(json_fd, "0x%.2X%.2X", packet_fp.e_curves[arse], packet_fp.e_curves[arse+1]);
				if ((arse + 1) < (packet_fp.e_curves[0]*256 + packet_fp.e_curves[1])) {
					fprintf(json_fd, " ");
				}
			}
			fprintf(json_fd, "\"");
		}

		if(packet_fp.sig_alg != NULL) {
			fprintf(json_fd, ", \"sig_alg\": \"");

			for (arse = 4 ; arse <= (packet_fp.sig_alg[0]*256 + packet_fp.sig_alg[1]) &&
				(packet_fp.sig_alg[0]*256 + packet_fp.sig_alg[1]) > 4 ; arse = arse + 2) {

				fprintf(json_fd, "0x%.2X%.2X", packet_fp.sig_alg[arse], packet_fp.sig_alg[arse+1]);
				if ((arse + 1) < (packet_fp.sig_alg[0]*256 + packet_fp.sig_alg[1])) {
					fprintf(json_fd, " ");
				}
			}
			fprintf(json_fd, "\"");
		}

		if(packet_fp.ec_point_fmt != NULL) {
			fprintf(json_fd, ", \"ec_point_fmt\": \"");

			// Jumping to "3" to get past the second length parameter... errrr... why?
			for (arse = 3 ; arse <= (packet_fp.ec_point_fmt[0]*256 + packet_fp.ec_point_fmt[1]) + 1 ; arse++) {
				fprintf(json_fd, "0x%.2X", packet_fp.ec_point_fmt[arse]);
				if ((arse + 1) < (packet_fp.ec_point_fmt[0]*256 + packet_fp.ec_point_fmt[1]) + 2) {
					fprintf(json_fd, " ");
				}
			}
			fprintf(json_fd, "\"");
		}

		if(packet_fp.server_name != NULL) {
			fprintf(json_fd, ", \"server_name\": \"");
			for (arse = 7 ; arse <= (packet_fp.server_name[0]*256 + packet_fp.server_name[1]) + 1 ; arse++) {
				if (packet_fp.server_name[arse] > 0x20 && packet_fp.server_name[arse] < 0x7b)
					fprintf(json_fd, "%c", packet_fp.server_name[arse]);
				else
					fprintf(json_fd, "*");
			}
			fprintf(json_fd, "\"");
		}


		fprintf(json_fd, "}\n");

		/* **************************** */
		/* END OF RECORD - OR SOMETHING */
		/* **************************** */
	}

}

int main(int argc, char **argv) {

	char *dev = NULL;					/* capture device name */
	char *unpriv_user = NULL;					/* User for dropping privs */
	char errbuf[PCAP_ERRBUF_SIZE];				/* error buffer */
	pcap_t *handle = NULL;						/* packet capture handle */

	char *filter_exp = default_filter;
	int arg_start = 1, i;
	struct bpf_program fp;					/* compiled filter program (expression) */

	extern FILE *json_fd, *struct_fd;
	extern int show_drops;
	show_drops = 0;

	/* Make sure pipe sees new packets unbuffered. */
	setvbuf(stdout, (char *)NULL, _IOLBF, 0);

	if (argc == 1) {
		print_usage(argv[0]);
		exit(-1);
	}
	/* Do the -something switches  - yes this isn't very nice and doesn't support -abcd */
	for (i = arg_start; i < argc && argv[i][0] == '-' ; i++) {
		switch (argv[i][1]) {
			case '?':
			case 'h':
				print_usage(argv[0]);
				exit(0);
				break;
			case 'p':
				/* Open the file */
				/* Check if interface already set */
				if (handle != NULL) {
					printf("-p and -i are mutually exclusive\n");
					exit(-1);
				}
				handle = pcap_open_offline(argv[++i], errbuf);
				printf("Reading from file: %s\n", argv[i]);
				break;
			case 'i':
				/* Open the interface */
				/* Check if file already successfully opened, if bad filename we can fail to sniffing */
				if (handle != NULL) {
					printf("-p and -i are mutually exclusive\n");
					exit(-1);
				}
				handle = pcap_open_live(argv[++i], SNAP_LEN, 1, 1000, errbuf);
				printf("Using interface: %s\n", argv[i]);
				break;
			case 'j':
				/* JSON output to file */
				if((json_fd = fopen(argv[++i], "a")) == NULL) {
					printf("Cannot open JSON file for output\n");
					exit(-1);
				}
				setvbuf(json_fd, (char *)NULL, _IOLBF, 0);
				break;
			case 's':
				/* JSON output to stdout */
				if((json_fd = fopen("/dev/stdout", "a")) == NULL) {
					printf("Cannot open JSON file for output\n");
					exit(-1);
				}
				break;
			case 'd':
				/* Show Dropped Packet Info */
				show_drops = 1;
				break;
			case 'u':
				/* User for dropping privileges to */
				unpriv_user = argv[++i];
				break;
			default :
				printf("Unknown option '%s'\n", argv[i]);
				exit(-1);
				break;

		}
	}

	/* Interface should already be opened, we can drop privs now */
	if (unpriv_user != NULL) {
		if (setgid(getgid()) == -1) {
  		fprintf(stderr, "WARNING: could not drop group privileges\n");
		}
		if (setuid(atoi(unpriv_user)) == -1) {
		  fprintf(stderr, "WARNING: could not drop privileges to specified UID\n");
		}
	}

	/* XXX HORRIBLE HORRIBLE KLUDGE TO AVOID if's everywhere.  I KNOW OK?! */
	if(json_fd == NULL) {
		if((json_fd = fopen("/dev/null", "a")) == NULL) {
			printf("Cannot open JSON file (/dev/null) for output\n");
			exit(-1);
		}
	}

	if (handle == NULL) {
		fprintf(stderr, "Couldn't open source %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	/* netmask is set to 0 because we don't care and it saves looking it up :) */
	if (pcap_compile(handle, &fp, default_filter, 0, 0) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}


	/* OK, Checks are done, but we still need to set some stuff up before we go looping */



	/* now we can set our callback function */
	pcap_loop(handle, -1, got_packet, NULL);

	/* This only occurs with pcap, not live capture, need signal shiz XXX */

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	return 0;
}
