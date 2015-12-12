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
// XXX Add UDP support (in theory very easy)
// XXX enhance search to include sorting per list/thread/shard/thingy
// XXX add 6in4 support (should be as simple as UDP and IPv6... in theory)

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

/* For TimeStamping from pcap_pkthdr */
#include <time.h>

/* For the signal handler stuff */
#include <signal.h>

/* And my own signal handler functions */
#include "signal.c"

/* My own header sherbizzle */
#include "fingerprintls.h"

/* Going to start breaking this up into neater functions/files.  The first of which */
/* is the fpdb management stuff */
//#include "fpdb.c"

/* Compare extensions in packet *packet with fingerprint *fingerprint */
int extensions_compare(uint8_t *packet, uint8_t *fingerprint, int length, int count) {
	/* XXX check that all things passed to this _are_ uint8_t and we're not only partially checking stuff that may be longer!!!! */
	/*
		Return values are:
		0 - No match
		1 - Exact match
		2 - Fuzzy match
	*/
	int x = 0;
	int y = 0;
	int retval = 1;
	for (; x < length ;) {
		if (((uint8_t) packet[x] != fingerprint[y] ) || ((uint8_t) packet[x+1] != fingerprint[y+1])) {
			/* Perform a fuzzy search on "optional" extensions here */
			/*

			Experimenting with fuzzy matches as certain extensions can vary with one client (looking at you Chrome!)
			0x7550 - "TLS Channel ID" - https://tools.ietf.org/html/draft-balfanz-tls-channelid-01.  Used for binding authentication tokens, extensions_compare
			0x0015 - "Padding" - Can totally discard this, because padding.
			0x0010 - "Application-Layer Protocol Negotiation" - https://tools.ietf.org/html/rfc7301

			switch() {
				case 0x7550:
				case 0x0015:
				case 0x0010:
			}
			*/
			retval = 0;
			break;
		} else {
			y += 2;
			x = x + 4 + (packet[(x+2)]*256) + (packet[x+3]);
		}
	}
	return retval;
}


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
	fprintf(stderr, "    -f <fpdb>         Load the (binary) FingerPrint Database\n");
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

	extern FILE *json_fd;
	extern int newsig_count;
	extern char hostname[HOST_NAME_MAX];

	int size_ip = 0;
	int size_tcp;
	int size_payload;
	int size_vlan_offset=0;

	int ip_version=0;
	int af_type;
	char src_address_buffer[64];
	char dst_address_buffer[64];

	struct timeval packet_time;
	struct tm print_time;
	char printable_time[64];

	struct fingerprint_new *fp_current;			/* For navigating the fingerprint database */

	/* pointers to key places in the packet headers */
	const struct ether_header *ethernet;	/* The ethernet header [1] */
	const struct ipv4_header *ipv4;         /* The IPv4 header */
	const struct ip6_hdr *ipv6;             /* The IPv6 header */
	const struct tcp_header *tcp;           /* The TCP header */
	const u_char *payload;                  /* Packet payload */

	/* Different to struct fingerprint in fpdb.h, this is for building new fingerprints */
	struct tmp_fingerprint {
		uint16_t 	id;
		char 			desc[312];
		uint16_t 	record_tls_version;
		uint16_t 	tls_version;
		uint16_t 	ciphersuite_length;
		uint8_t		*ciphersuite;
		uint8_t		compression_length;
		uint8_t		*compression;
		uint16_t 	extensions_length;
		uint8_t		*extensions;
		uint16_t	e_curves_length;
		uint8_t		*e_curves;
		uint16_t 	sig_alg_length;
		uint8_t		*sig_alg;
		uint16_t 	ec_point_fmt_length;
		uint8_t		*ec_point_fmt;
		char 			*server_name;
		int				padding_length;
	} packet_fp;

	/* ************************************* */
	/* Anything we need from the pcap_pkthdr */
	/* ************************************* */

	/* In theory time doesn't need to be first because it's saved in the PCAP
		 header, however I am keeping it here incase we derive it from somewhere
		 else in future and we want it early in the process. */

	packet_time = pcap_header->ts;
	print_time = *localtime(&packet_time.tv_sec);
	strftime(printable_time, sizeof printable_time, "%Y-%m-%d %H:%M:%S", &print_time);


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
			//case ETHERTYPE_IPV6:
			case 0x86dd:
				/* IPv6 */
				ip_version=6;
				af_type=AF_INET6;
				break;
			default:
				/* Something's gone wrong... Doesn't appear to be a valid ethernet frame? */
				if (show_drops)
					fprintf(stderr, "[%s] Malformed Ethernet frame\n", printable_time);
				return;
		}
	}

	switch(ip_version) {
		case 4:
		/* IP Header */
		ipv4 = (struct ipv4_header*)(packet + SIZE_ETHERNET + size_vlan_offset);
		size_ip = IP_HL(ipv4)*4;

		if (size_ip < 20) {
			/* This is just wrong, not even bothering */
			if(show_drops)
				fprintf(stderr, "[%s] Packet Drop: Invalid IP header length: %u bytes\n", printable_time, size_ip);
			return;
		}

		/* TCP Header */
		if (ipv4->ip_p != IPPROTO_TCP) {
			/* Not TCP, not trying.... don't care.  The BPF filter should
			 * prevent this happening, but if I remove it you can guarantee I'll have
			 * forgotten an edge case :) */
			 if (show_drops)
			 	fprintf(stderr, "[%s] Packet Drop: non-TCP made it though the filter... weird\n", printable_time);
			return;
		}
		break;

		case 6:
		/* IP Header */
		ipv6 = (struct ip6_hdr*)(packet + SIZE_ETHERNET + size_vlan_offset);
		size_ip = 40;

		/* TODO: Parse 'next header(s)' */
		//printf("IP Version? %i\n",ntohl(ipv6->ip6_vfc)>>28);
		//printf("Traffic Class? %i\n",(ntohl(ipv6->ip6_vfc)&0x0ff00000)>>24);
		//printf("Flow Label? %i\n",ntohl(ipv6->ip6_vfc)&0xfffff);
		//printf("Payload? %i\n",ntohs(ipv6->ip6_plen));
		//printf("Next Header? %i\n",ipv6->ip6_nxt);

		/* Note: Because the PCAP Libraries don't allow a BPF to adequately process TCP headers on IPv6
			 packets we have had to accept all IPv6 TCP packets and so extra processing here to ensure
			 that they're CLIENT_HELLO that is actually done in the BPF for v4.... damn you PCAP!! */

		// XXX These lines are duplicated, will de-dupe later this is for testing without breaking :)
		tcp = (struct tcp_header*)(packet + SIZE_ETHERNET + size_vlan_offset + size_ip);
		payload = (u_char *)(packet + SIZE_ETHERNET + size_vlan_offset + size_ip + (tcp->th_off * 4));
		// Emulating: "(tcp[tcp[12]/16*4]=22 and (tcp[tcp[12]/16*4+5]=1) and (tcp[tcp[12]/16*4+9]=3) and (tcp[tcp[12]/16*4+1]=3))"
		if(!(payload[0] == 22 && payload[5] == 1 && payload[9] == 3 && payload[1] == 3))
			return; /* Doesn't match our not BPF, BPF.... BAILING OUT!! */


		/* Sanity Check... Should be IPv6 */
		if ((ntohl(ipv6->ip6_vfc)>>28)!=6){
			if(show_drops)
				fprintf(stderr, "[%s] Packet Drop: Invalid IPv6 header\n", printable_time);
			return;
		}

		switch(ipv6->ip6_nxt){
			case 6:		/* TCP */
				break;
			case 17:	/* UDP */
			case 58:	/* ICMPv6 */
				if(show_drops)
				 	fprintf(stderr, "[%s] Packet Drop: non-TCP made it though the filter... weird\n", printable_time);
				return;

			default:
				printf("[%s] Packet Drop: Unhandled IPv6 next header: %i\n",printable_time, ipv6->ip6_nxt);
				return;
		}

	}

	/* Yay, it's TCP, let's set the pointer */
	tcp = (struct tcp_header*)(packet + SIZE_ETHERNET + size_vlan_offset + size_ip);

	size_tcp = (tcp->th_off * 4);
	if (size_tcp < 20) {
		/* Not even trying if this is the case.... kthnxbai */
		if(show_drops)
			printf("[%s] Packet Drop: Invalid TCP header length: %u bytes\n", printable_time, size_tcp);
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
				printf("[%s] Packet Drop: Bad TLS Version\n", printable_time);
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
			printf("[%s] Packet Drop: Session ID looks bad\n", printable_time);
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

			/* Some potential new extenstions to exploit for fingerprint material */
			/* Need to be tested for consistent values before deploying though    */
			case 0x0015:
				/* Padding */
				/* XXX Need to check if padding length is consistent or varies (varies is not useful to us) */
				break;
			case 0x0010:
				/* application_layer_protocol_negotiation */

				break;
			case 0x000F:
				/* HeartBeat (as per padding, is this consistent?) */

				break;
		}


		/* Increment past the payload of the extensions */
		ext_id += (cipher_data[ext_id + 2]*256) + cipher_data[ext_id + 3] + 3;

	}


	/* ********************************************* */
	/* The "compare to the fingerprint database" bit */
	/* ********************************************* */
//	int fp_loop, arse;
	int arse;

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

	/* ************************* */
	/* New Matching thinger test */
	/* ************************* */
	//for(fp_current = fp_first ; fp_current != NULL; fp_current = fp_current->next) {
	for(fp_current = search[((packet_fp.ciphersuite_length & 0x000F) >> 1 )][((packet_fp.tls_version) & 0x00FF)] ;
		fp_current != NULL; fp_current = fp_current->next) {

		//printf("Trying... %.*s\n", fp_current->desc_length, fp_current->desc);
		if ((packet_fp.record_tls_version == fp_current->record_tls_version) &&
			(packet_fp.tls_version == fp_current->tls_version) &&

			/* XXX extensions_length is misleading!  Length is variable, it is a count of
			   uint8_t's that makes the extensions _list_.  Furthermore, these values are
				 in pairs, so the count is actually half this....  Handle much more carefully
				 kthnxbai */

			/* Note: check lengths match first, the later comparisons assume these already match */
			(packet_fp.ciphersuite_length == fp_current->ciphersuite_length) &&
			(packet_fp.compression_length == fp_current->compression_length) &&
			((ext_count * 2) == fp_current->extensions_length) &&
			(packet_fp.e_curves_length == fp_current->curves_length) &&
			(packet_fp.sig_alg_length == fp_current->sig_alg_length) &&
			(packet_fp.ec_point_fmt_length == fp_current->ec_point_fmt_length) &&

			!(bcmp(packet_fp.ciphersuite, fp_current->ciphersuite, fp_current->ciphersuite_length)) &&
			!(bcmp(packet_fp.compression, fp_current->compression, fp_current->compression_length)) &&
			extensions_compare(packet_fp.extensions, fp_current->extensions, ext_len, fp_current->extensions_length) &&
			!(bcmp(realcurves, fp_current->curves, fp_current->curves_length)) &&
			!(bcmp(realsig_alg, fp_current->sig_alg, fp_current->sig_alg_length)) &&
			!(bcmp(realec_point_fmt, fp_current->ec_point_fmt, fp_current->ec_point_fmt_length))) {

				/* Whole criteria match.... woo! */
				matchcount++;
				printf("[%s] Fingerprint Matched: \"%.*s\" %s connection from %s:%i to ", printable_time, fp_current->desc_length ,fp_current->desc, ssl_version(fp_current->tls_version),
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
				// Fuzzy Match goes here (if we ever want it)
		}
	}

	/* ********************************************* */


	if(matchcount == 0) {
		newsig_count++;

		/* The fingerprint was not matched.  So let's just add it to the internal DB :) */
		/* Allocate memory to store it */
		// XXX Cannot do this if we go multi-threaded, locking (urg!) maybe?!!!!!
		printf("[%s] New FingerPrint [%i] Detected, dynamically adding to in-memory fingerprint database\n", printable_time, newsig_count);
		// XXX Should really check if malloc works ;)
		fp_current = malloc(sizeof(struct fingerprint_new));
		/* Update pointers, put top of list */
		fp_current->next = search[((packet_fp.ciphersuite_length & 0x000F) >> 1 )][((packet_fp.tls_version) & 0x00FF)];
		search[((packet_fp.ciphersuite_length & 0x000F) >> 1 )][((packet_fp.tls_version) & 0x00FF)] = fp_current;
		/* Populate the fingerprint */
		fp_current->fingerprint_id = 0;
		fp_current->desc_length = strlen("Dynamic ") + strlen(hostname) + 7; // 7 should cover the max uint16_t + space
		fp_current->desc = malloc(fp_current->desc_length);
		sprintf(fp_current->desc, "Dynamic %s %d", hostname, newsig_count);
		fp_current->record_tls_version = packet_fp.record_tls_version;
	  fp_current->tls_version = packet_fp.tls_version;
	  fp_current->ciphersuite_length = packet_fp.ciphersuite_length;
		fp_current->compression_length = packet_fp.compression_length; // Actually *IS* a uint8_t field!!!  ZOMG
	  fp_current->extensions_length = (ext_count * 2);
	  fp_current->curves_length = packet_fp.e_curves_length;
		fp_current->sig_alg_length = packet_fp.sig_alg_length;
		fp_current->ec_point_fmt_length = packet_fp.ec_point_fmt_length;
		// XXX This little malloc fest should be rolled into one.
		fp_current->ciphersuite = malloc(fp_current->ciphersuite_length);
	  fp_current->compression = malloc(fp_current->compression_length);
  	fp_current->extensions = malloc(fp_current->extensions_length);
	  fp_current->curves = malloc(fp_current->curves_length);
  	fp_current->sig_alg = malloc(fp_current->sig_alg_length);
	  fp_current->ec_point_fmt = malloc(fp_current->ec_point_fmt_length);
		// Copy the data over (except extensions)
		memcpy(fp_current->ciphersuite, packet_fp.ciphersuite, fp_current->ciphersuite_length);
		memcpy(fp_current->compression, packet_fp.compression, fp_current->compression_length);
		memcpy(fp_current->curves, realcurves, fp_current->curves_length);
		memcpy(fp_current->sig_alg, realsig_alg, fp_current->sig_alg_length);
		memcpy(fp_current->ec_point_fmt, realec_point_fmt, fp_current->ec_point_fmt_length);

		// Load up the extensions
		int unarse = 0;
		for (arse = 0 ; arse < ext_len ;) {
			fp_current->extensions[unarse] = (uint8_t) packet_fp.extensions[arse];
			fp_current->extensions[unarse+1] = (uint8_t) packet_fp.extensions[arse+1];
			unarse += 2;
			arse = arse + 4 + (packet_fp.extensions[(arse+2)]*256) + (packet_fp.extensions[arse+3]);
		}

		/* If selected output in the normal stream */

		printf("[%s] New Fingerprint \"%s\": %s connection from %s:%i to ", printable_time, fp_current->desc, ssl_version(packet_fp.tls_version),
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
		printf("\"\n");

		// Should just for json_fd being /dev/null and skip .. optimisation...
		// or make an output function linked list XXX
		snprintf(packet_fp.desc,sizeof(packet_fp.desc),"%s %s:%i -> %s:%i", fp_current->desc, src_address_buffer, ntohs(tcp->th_sport), dst_address_buffer, ntohs(tcp->th_dport));
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
	extern pcap_t *handle;						/* packet capture handle */

	char *filter_exp = default_filter;
	int arg_start = 1, i;
	extern struct bpf_program fp;					/* compiled filter program (expression) */

	extern FILE *json_fd, *fpdb_fd;
	int filesize;
	uint8_t *fpdb_raw = NULL;
	int	fp_count = 0;
	extern int show_drops;
	extern char hostname[HOST_NAME_MAX];
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
			case 'f':
				/* Read the *new* *sparkly* *probably broken* :) binary Fingerprint Database from file */
				/* In the future this will be to override the default location as this will be the default format */
				if((fpdb_fd = fopen(argv[++i], "r")) == NULL) {
					printf("Cannot open fingerprint database file\n");
					exit(-1);
				}

				break;
			default :
				printf("Unknown option '%s'\n", argv[i]);
				exit(-1);
				break;

		}
	}

	/* Checks required directly after switches are set */

	/* Fingerprint DB to load */
	/* This needs to be before the priv drop in case the fingerprint db requires root privs to read */
	if(fpdb_fd == NULL) {
		/* No filename set, trying the current directory */
		if((fpdb_fd = fopen("tlsfp.db", "r")) == NULL) {
			printf("Cannot open fingerprint database file (try -f)\n");
			printf("(This is a new feature, tlsfp.db should be in the source code directory)\n");
			exit(-1);
		}

	}

	/* Interface should already be opened, and files read we can drop privs now */
	/* This should stay the first action as lowering privs reduces risk from any subsequent actions */
	/* being poorly implimented and running as root */
	if (unpriv_user != NULL) {
		if (setgid(getgid()) == -1) {
  		fprintf(stderr, "WARNING: could not drop group privileges\n");
		} else {
			fprintf(stderr, "Dropped effective group successfully\n");
		}
		if (setuid(atoi(unpriv_user)) == -1) {
			fprintf(stderr, "WARNING: could not drop privileges to specified UID\n");
		} else {
			fprintf(stderr, "Changed UID successfully\n");
		}
	}

	// Register signal Handlers
	if(!(register_signals())) {
		printf("Could not register signal handlers\n");
		exit(0);
	}


	/* XXX Temporary home, but need to test as early in the cycle as possible for now */
	/* Load binary rules blob and parse */

	/* XXX This if can go when this is "the way" */
	if(fpdb_fd != NULL) {
		/* Find the filesize (seek, tell, seekback) */
		fseek(fpdb_fd, 0L, SEEK_END);
		filesize = ftell(fpdb_fd);
		fseek(fpdb_fd, 0L, SEEK_SET);

		/* Allocate memory and store the file in fpdb_raw */
		fpdb_raw = malloc(filesize);
		if (fread(fpdb_raw, 1, filesize, fpdb_fd) == filesize) {
			// printf("Yay, looks like the FPDB file loaded ok\n");
			fclose(fpdb_fd);
		} else {
			printf("There seems to be a problem reading the FPDB file\n");
			fclose(fpdb_fd);
			exit(-1);
		}
	}

	/* Check and move past the version header (quit if it's wrong) */
	if (*fpdb_raw == 0) {
		fpdb_raw++;
	} else {
		printf("Unknown version of FPDB file\n");
		exit(-1);
	}

	int x, y;
	//extern struct fingerprint_new *fp_first;
	struct fingerprint_new *fp_current;
	extern struct fingerprint_new *search[8][4];

	/* Initialise so that we know when we are on the first in any one chain */
	for (x = 0 ; x < 8 ; x++) {
		for (y = 0 ; y < 4 ; y++) {
			search[x][y] = NULL;
		}
	}

	/* Filesize -1 because of the header, loops through the file, one loop per fingerprint */
	for (x = 0 ; x < (filesize-1) ; fp_count++) {
		/* Allocating one my one instead of in a block, may revise this plan later */
		/* This will only save time on startup as opposed to during operation though */

		/* Allocate out the memory for the one signature */
		fp_current = malloc(sizeof(struct fingerprint_new));

		// XXX consider copied (i.e. length) values being free'd to save a little RAM here and there <-- future thing

		fp_current->fingerprint_id = (uint16_t) ((uint16_t)*(fpdb_raw+x) << 8) + ((uint8_t)*(fpdb_raw+x+1));
		x += 2;
		fp_current->desc_length =  (uint16_t) ((uint16_t)*(fpdb_raw+x) << 8) + ((uint8_t)*(fpdb_raw+x+1));
		fp_current->desc = (char *)fpdb_raw+x+2;

		x += (uint16_t) ((*(fpdb_raw+x) >> 16) + (*(fpdb_raw+x+1)) + 1); // Skip the description

		fp_current->record_tls_version = (uint16_t) ((uint16_t)*(fpdb_raw+x+1) << 8) + ((uint8_t)*(fpdb_raw+x+2));
		fp_current->tls_version = (uint16_t) ((uint16_t)*(fpdb_raw+x+3) << 8) + ((uint8_t)*(fpdb_raw+x+4));
		fp_current->ciphersuite_length = (uint16_t) ((uint16_t)*(fpdb_raw+x+5) << 8) + ((uint8_t)*(fpdb_raw+x+6));
		fp_current->ciphersuite = fpdb_raw+x+7;

		x += (uint16_t) ((*(fpdb_raw+x+5) >> 16) + (*(fpdb_raw+x+6)))+7; // Skip the ciphersuites

		fp_current->compression_length = *(fpdb_raw+x);
		fp_current->compression = fpdb_raw+x+1;

		x += (*(fpdb_raw+x))+1; // Skip over compression algo's

		fp_current->extensions_length = (uint16_t) ((uint16_t)*(fpdb_raw+x) << 8) + ((uint8_t)*(fpdb_raw+x+1));
		fp_current->extensions = fpdb_raw+x+2;

		x += (uint16_t)((*(fpdb_raw+x) >> 16) + *(fpdb_raw+x+1))+2; // Skip extensions list (not extensions - just the list)

		/* Lengths for the extensions which do not exist have already been set to 0 by fingerprintout.py */

		fp_current->curves_length = (uint16_t) ((uint16_t)*(fpdb_raw+x) << 8) + ((uint8_t)*(fpdb_raw+x+1));

		if(fp_current->curves_length == 0) {
			fp_current->curves = NULL;
		} else {
			fp_current->curves = fpdb_raw+x+2;
		}

		x += (uint16_t)((*(fpdb_raw+x) >> 16) + *(fpdb_raw+x+1))+2;  // Skip past curves

		fp_current->sig_alg_length = (uint16_t) ((uint16_t)*(fpdb_raw+x) << 8) + ((uint8_t)*(fpdb_raw+x+1));

		if(fp_current->sig_alg_length == 0) {
			fp_current->sig_alg = NULL;
		} else {
			fp_current->sig_alg = fpdb_raw+x+2;
		}

		x += (uint16_t)((*(fpdb_raw+x) >> 16) + *(fpdb_raw+x+1))+2;  // Skip past signature algorithms

		fp_current->ec_point_fmt_length = (uint16_t) ((uint16_t)*(fpdb_raw+x) << 8) + ((uint8_t)*(fpdb_raw+x+1));

		if(fp_current->ec_point_fmt_length == 0) {
			fp_current->ec_point_fmt = NULL;
		} else {
			fp_current->ec_point_fmt = fpdb_raw+x+2;
		}
		x += (uint16_t)((*(fpdb_raw+x) >> 16) + *(fpdb_raw+x+1))+2;

		/* Multi-array of pointers to appropriate (smaller) list */
		/* XXX This should still be ordered for faster search */
		if(search[((fp_current->ciphersuite_length & 0x000F) >> 1 )][((fp_current->tls_version) & 0x00FF)] == NULL) {
			search[((fp_current->ciphersuite_length & 0x000F) >> 1 )][((fp_current->tls_version) & 0x00FF)] = fp_current;
		} else {
			fp_current->next = search[((fp_current->ciphersuite_length & 0x000F) >> 1 )][((fp_current->tls_version) & 0x00FF)];
			search[((fp_current->ciphersuite_length & 0x000F) >> 1 )][((fp_current->tls_version) & 0x00FF)] = fp_current;
		}
	}
	/* Terminate the linked list */
	fp_current->next = NULL;
	printf("Loaded %i signatures\n", fp_count);

	/* XXX END TESTING OF BINARY RULES */


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

	/* setup hostname variable for use in logs (incase of multiple hosts) */
	if(gethostname(hostname, HOST_NAME_MAX) != 0) {
		sprintf(hostname, "unknown");
	}


	/* now we can set our callback function */
	pcap_loop(handle, -1, got_packet, NULL);

	/* This only occurs with pcap, not live capture, need signal shiz XXX */

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	return 0;
}
