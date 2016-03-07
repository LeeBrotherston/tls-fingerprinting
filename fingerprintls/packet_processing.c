// XXX as expected there is a memory leak, because I've been a bit yeeehaw with malloc in doing this test
// check through the code to make sure mallocs and frees are all matched up. (may be fixed?)

// XXX reuse alloc'd space


uint shardnum (uint16_t port1, uint16_t port2, uint16_t maxshard) {
				return (((port1 >> 8) + (port2 >> 8)) & (maxshard - 1));
}



void got_packet(u_char *args, const struct pcap_pkthdr *pcap_header, const u_char *packet) {
		/* ************************************************************************* */
		/* Variables, gotta have variables, and structs and pointers....  and things */
		/* ************************************************************************* */

		extern FILE *json_fd, *log_fd;
		extern int newsig_count;
		extern char hostname[HOST_NAME_MAX];


		int size_ip = 0;
		int size_tcp;
		uint size_payload;  //  Check all these for appropiate variable size.  Was getting signed negative value and failing tests XXX
		int size_vlan_offset=0;
		int arse;  // Random counter - relocated to allow use elsewhere during testing


		int ip_version=0;
		int af_type;
		char src_address_buffer[64];
		char dst_address_buffer[64];

		struct timeval packet_time;
		struct tm print_time;
		char printable_time[64];

		struct fingerprint_new *fp_nav;			/* For navigating the fingerprint database */
		static struct fingerprint_new *fp_packet = NULL;			/* Generated fingerprint for incoming packet */
		static uint16_t	extensions_malloc = 0;							/* how much is currently allocated for the extensions field */
		extern pcap_dumper_t *output_handle;					/* output to pcap handle */

		/* pointers to key places in the packet headers */
		struct ether_header *ethernet;	/* The ethernet header [1] */
		struct ipv4_header *ipv4;         /* The IPv4 header */
		struct ip6_hdr *ipv6;             /* The IPv6 header */
		struct tcp_header *tcp;           /* The TCP header */
		struct udp_header *udp;           /* The UDP header */
		struct teredo_header *teredo;			/* Teredo header */


		u_char *payload;                  /* Packet payload */

		char *server_name;						/* Server name per the extension */

		/*
			Check if this is uninitialised at this point and initialise if so.  This saves us copying
			in the event that we need a new fingerprint, we already have a populated fingerprint structs
			for the most part (barring a couple of memcpy's).  This should reduce the time to insert
			new signatures.
		*/
		if(fp_packet == NULL) {
			fp_packet = malloc(sizeof(struct fingerprint_new));
			if(fp_packet == NULL) {
				printf("Malloc Error (fp_packet)\n");
				exit(0);
			}
		}

		/* ************************************* */
		/* Anything we need from the pcap_pkthdr */
		/* ************************************* */

		/*
			In theory time doesn't need to be first because it's saved in the PCAP
			header, however I am keeping it here incase we derive it from somewhere
			else in future and we want it early in the process.
		*/

		packet_time = pcap_header->ts;
		print_time = *localtime(&packet_time.tv_sec);
		strftime(printable_time, sizeof printable_time, "%Y-%m-%d %H:%M:%S", &print_time);


		/* ******************************************** */
		/* Set pointers to the main parts of the packet */
		/* ******************************************** */

		/*
			Ethernet
		*/

		/*
			Section to deal with random low layer stuff before we get to IP
		*/

		ethernet = (struct ether_header*)(packet);
		switch(ntohs(ethernet->ether_type)) {
			/*
				De-802.1Q things if needed.  This isn't in the switch below so that we don't have to loop
				back around for IPv4 vs v6 ethertype handling.  This is a special case that we just detangle
				upfront.  Also avoids a while loop, woo!
			*/
			case ETHERTYPE_VLAN:
				// Using loop to account for double tagging (can you triple?!)
				for(size_vlan_offset=4;  ethernet->ether_type == ETHERTYPE_VLAN ; size_vlan_offset+=4) {
					ethernet = (struct ether_header*)(packet+size_vlan_offset);
				}
				break;
			/* PPPoE */
			case 0x8864:
				// XXX Need to research further but seems skipping 8 bytes is all we need?  But how.... hmmmm...
				//ethernet = (struct ether_header*)(packet + size_vlan_offset + 8);

				//  This is just a placeholder for now.  BPF will probably need updating.
				printf("PPPoE\n");
				break;
		}

		// Now we can deal with what the ether_type is
		switch(ntohs(ethernet->ether_type)){
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


		/*
			Sadly BPF filters are not equal between IPv4 and IPv6 so we cannot rely on them for everything, so
			this section attempts to cope with that.
		*/

		/*
			IP headers
		*/
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
				if(show_drops) {
					fprintf(stderr, "[%s] Packet Passed header length: %u bytes\n", printable_time, size_ip);
				}

				/* Protocol */
				switch(ipv4->ip_p) {
					case IPPROTO_TCP:
						break;

					case IPPROTO_UDP:
						/*
							As it stands currently, the BPF should ensure that the *only* UDP is Teredo with TLS IPv6 packets inside,
							thus I'm going to assume that is the case for now and set ip_version to 5 (4 to 6 intermediary as I will
							never have to support actual IPv5).
						*/
						ip_version = 7;

						udp = (struct udp_header*)(packet + SIZE_ETHERNET + size_vlan_offset + size_ip);
						teredo = (struct teredo_header*)(udp + 1);  /* +1 is UDP header, not bytes ;) */
						//tcp = (struct tcp_header*)(packet + SIZE_ETHERNET + size_vlan_offset + size_ip + 8 + sizeof(struct teredo_header));

						/* setting offset later with size_ip manipulation...  may need to ammend this */
						size_ip += sizeof(struct udp_header) + sizeof(struct teredo_header);
						break;

					case 0x29:
						/* Not using this yet, but here ready for when I impliment 6in4 de-encapsultion (per teredo) */
						ip_version = 8;  // No reason... YOLO
						ipv6 = (struct ip6_hdr*)(packet + SIZE_ETHERNET + size_vlan_offset + sizeof(struct ipv4_header));
						size_ip += 40;
						break;

					default:
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

		/*
			TCP/UDP/Cabbage/Jam
		*/
		/* Yay, it's TCP, let's set the pointer */
		tcp = (struct tcp_header*)(packet + SIZE_ETHERNET + size_vlan_offset + size_ip);

		size_tcp = (tcp->th_off * 4);
		if (size_tcp < 20) {
			/* Not even trying if this is the case.... kthnxbai */
			if(show_drops)
				printf("[%s] Packet Drop: Invalid TCP header length: %u bytes\n", printable_time, size_tcp);
			return;
		}

		/*
			Packet Payload
		*/

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
					printf("[%s] Packet Drop: Bad TLS Version %X%X\n", printable_time, payload[OFFSET_HELLO_VERSION], payload[OFFSET_HELLO_VERSION+1]);
					//printf("%X %X %X %X\n",payload[OFFSET_HELLO_VERSION-8],payload[OFFSET_HELLO_VERSION-7],payload[OFFSET_HELLO_VERSION-6],payload[OFFSET_HELLO_VERSION-5]);
					//printf("%X %X %X %X\n",payload[OFFSET_HELLO_VERSION-4],payload[OFFSET_HELLO_VERSION-3],payload[OFFSET_HELLO_VERSION-2],payload[OFFSET_HELLO_VERSION-1]);
					//printf("%X %X %X %X\n",payload[OFFSET_HELLO_VERSION],payload[OFFSET_HELLO_VERSION+1],payload[OFFSET_HELLO_VERSION+2],payload[OFFSET_HELLO_VERSION+3]);
					//printf("%X %X %X %X\n",payload[OFFSET_HELLO_VERSION+4],payload[OFFSET_HELLO_VERSION+5],payload[OFFSET_HELLO_VERSION+6],payload[OFFSET_HELLO_VERSION+7]);
					//printf("%X %X %X %X\n",payload[OFFSET_HELLO_VERSION+8],payload[OFFSET_HELLO_VERSION+9],payload[OFFSET_HELLO_VERSION+10],payload[OFFSET_HELLO_VERSION+11]);
				return;
		}

		/* Check the size of the sessionid */
		const u_char *packet_data = &payload[OFFSET_SESSION_LENGTH];
		if (size_payload < OFFSET_SESSION_LENGTH + packet_data[0] + 3) {
			if(show_drops)
				printf("[%s] Packet Drop: Session ID looks bad [%i] [%i]\n", printable_time, size_payload, (OFFSET_SESSION_LENGTH + packet_data[0] + 3) );
			return;
		}

		/* ************************************************************************ */
		/* The bit that grabs the useful info from packets (or sets pointers to it) */
		/* ************************************************************************ */

		/* ID and Desc (with defaults for unknown fingerprints) */
		fp_packet->fingerprint_id = 0;
		switch(ip_version) {
			case 7:
				/* Temporarily Doing this to PoC teredo.  Will use outer and inner once it's working */
				/* IPv4 source and IPv6 dest is sorta what the connection is, so temping with that */
				inet_ntop(AF_INET,(void*)&ipv4->ip_src,src_address_buffer,sizeof(src_address_buffer));
				inet_ntop(AF_INET6,(void*)&teredo->ip6_dst,dst_address_buffer,sizeof(dst_address_buffer));
				break;
			case 4:
				inet_ntop(af_type,(void*)&ipv4->ip_src,src_address_buffer,sizeof(src_address_buffer));
				inet_ntop(af_type,(void*)&ipv4->ip_dst,dst_address_buffer,sizeof(dst_address_buffer));
				break;
			case 6:
				inet_ntop(af_type,(void*)&ipv6->ip6_src,src_address_buffer,sizeof(src_address_buffer));
				inet_ntop(af_type,(void*)&ipv6->ip6_dst,dst_address_buffer,sizeof(dst_address_buffer));
				break;
			case 8:
				inet_ntop(AF_INET,(void*)&ipv4->ip_src,src_address_buffer,sizeof(src_address_buffer));
				inet_ntop(AF_INET6,(void*)&ipv6->ip6_dst,dst_address_buffer,sizeof(dst_address_buffer));
		}


		/* TLS Version (Record Layer - not proper proper) */
		fp_packet->record_tls_version = (payload[1]*256) + payload[2];

		/* TLS Version */
		fp_packet->tls_version = (payload[OFFSET_HELLO_VERSION]*256) + payload[OFFSET_HELLO_VERSION+1];

		/* CipherSuite */
		packet_data += 1 + packet_data[0];
		u_short cs_len = packet_data[0]*256 + packet_data[1];
		/* Length */
		fp_packet->ciphersuite_length = (packet_data[0]*256) + packet_data[1];


		/*
			CipherSuites
		*/
		packet_data += 2; // skip cipher suites length
		fp_packet->ciphersuite = (uint8_t *)packet_data;

		/*
			Compression
		*/
		u_short comp_len = packet_data[cs_len];

		/*
			Length
		*/
		fp_packet->compression_length = comp_len;

		/*
			Compression List
		*/
		packet_data += cs_len + 1;
		fp_packet->compression = (uint8_t *)packet_data;

		/*
			Extensions
		*/
		u_short ext_len = packet_data[comp_len]*256 + packet_data[comp_len+1];
		int ext_id, ext_count = 0;

		/*
			Length
		*/
		packet_data += comp_len + 2;

		/*
			Set optional data to NULL in advance
		*/
		fp_packet->curves = NULL;
		fp_packet->sig_alg = NULL;
		fp_packet->ec_point_fmt = NULL;
		server_name = NULL;


		/*
			So this works - so overall length seems ok
		*/
		uint8_t *extensions_tmp_ptr = (uint8_t *)packet_data;

		/*
			If we are at the end of the packet we have no extensions, without this
			we will just run off the end of the packet into unallocated space :/
		*/
		if(packet_data - payload > size_payload) {
			ext_len = 0;
		}
		/* Loop through the extensions */
		fp_packet->extensions_length = 0;
		for (ext_id = 0; ext_id < ext_len ; ext_id++ ) {
			int ext_type;

			/* Set the extension type */
			ext_type = (packet_data[ext_id]*256) + packet_data[ext_id + 1];
			ext_count++;

			/* Handle some special cases */
			switch(ext_type) {
				case 0x000a:
					/* elliptic_curves */
					fp_packet->curves = (uint8_t *)&packet_data[ext_id + 2];
					/* 2 & 3, not 0 & 1 because of 2nd length field */
					fp_packet->curves_length = fp_packet->curves[2]*256 + fp_packet->curves[3];
					break;
				case 0x000b:
					/* ec_point formats */
					fp_packet->ec_point_fmt = (uint8_t *)&packet_data[ext_id + 2];
					fp_packet->ec_point_fmt_length = fp_packet->ec_point_fmt[2];
					//printf("ec point length: %i\n", fp_packet->ec_point_fmt_length);
					break;
				case 0x000d:
					/* Signature algorithms */
					fp_packet->sig_alg = (uint8_t *)&packet_data[ext_id + 2];
					fp_packet->sig_alg_length = fp_packet->sig_alg[2]*256 + fp_packet->sig_alg[3];
					break;
				case 0x0000:
					/* Definitely *NOT* signature-worthy
					 * but worth noting for debugging source
					 * of packets during signature creation.
					 */
					/* Server Name */
					server_name = (char *)&packet_data[ext_id+2];
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
			fp_packet->extensions_length = (ext_count * 2);

			/* Increment past the payload of the extensions */
			ext_id += (packet_data[ext_id + 2]*256) + packet_data[ext_id + 3] + 3;

			if((packet_data + ext_id) > (payload + size_payload)) {
				fprintf(stderr, "Offset Beyond end of packet %s:%i to ", src_address_buffer, ntohs(tcp->th_sport));
				fprintf(stderr, "%s:%i\n", dst_address_buffer, ntohs(tcp->th_dport));
				return;
			}

		}

		/* XXX This horrible kludge to get around the 2 length fields.  FIX IT! */
		// XXX Check that curves are working (being matched, etc)
		uint8_t *realcurves = fp_packet->curves;
		if (fp_packet->curves != NULL) {
			realcurves += 4;
		} else {
			realcurves = NULL;
			fp_packet->curves_length = 0;
		}
		/* ******************************************************************** */

		/* XXX This horrible kludge to get around the 2 length fields.  FIX IT! */
		uint8_t *realsig_alg = fp_packet->sig_alg;
			if(fp_packet->sig_alg != NULL) {
			realsig_alg += 4;
			fp_packet->sig_alg = realsig_alg;
		} else {
			realsig_alg = NULL;
			fp_packet->sig_alg_length = 0;
		}
		/* ******************************************************************** */

		/* XXX This horrible kludge to get around the 2 length fields.  FIX IT! */
		uint8_t *realec_point_fmt = fp_packet->ec_point_fmt;
		if(fp_packet->ec_point_fmt != NULL) {
			realec_point_fmt += 3;
		} else {
			realec_point_fmt = NULL;
			fp_packet->ec_point_fmt_length = 0;
		}
		/* ******************************************************************** */



		/*
			Extensions use offsets, etc so we can alloc those now.  Others however will just have pointers
			and we can malloc if it becomes a signature.  For this reason we have extensions_malloc to track
			the current size for easy reuse instead of consantly malloc and free'ing the space.
		*/

		if(extensions_malloc == 0) {
			fp_packet->extensions = malloc(fp_packet->extensions_length);
			extensions_malloc = fp_packet->extensions_length;
		} else{
			if(fp_packet->extensions_length > extensions_malloc) {
				fp_packet->extensions = realloc(fp_packet->extensions, fp_packet->extensions_length);
				extensions_malloc = fp_packet->extensions_length;
			}
		}
		if(fp_packet->extensions == NULL) {
			printf("Malloc Error (extensions)\n");
			exit(0);
		}

		// Load up the extensions
		int unarse = 0;
		for (arse = 0 ; arse < ext_len ;) {
			fp_packet->extensions[unarse] = (uint8_t) extensions_tmp_ptr[arse];
			fp_packet->extensions[unarse+1] = (uint8_t) extensions_tmp_ptr[arse+1];
			unarse += 2;
			arse = arse + 4 + (uint8_t)(extensions_tmp_ptr[(arse+2)]*256) + (uint8_t)(extensions_tmp_ptr[arse+3]);
		}

		/* ********************************************* */
		/* The "compare to the fingerprint database" bit */
		/* ********************************************* */


		int matchcount = 0;

		/* ************************* */
		/* New Matching thinger test */
		/* ************************* */
		for(fp_nav = search[((fp_packet->ciphersuite_length & 0x000F) >> 1 )][((fp_packet->tls_version) & 0x00FF)] ;
			fp_nav != NULL; fp_nav = fp_nav->next) {

			// XXX Need to optimise order and remove duplicate checks already used during indexing.
			if ((fp_packet->record_tls_version == fp_nav->record_tls_version) &&
				(fp_packet->tls_version == fp_nav->tls_version) &&
				/* XXX extensions_length is misleading!  Length is variable, it is a count of
				   uint8_t's that makes the extensions _list_.  Furthermore, these values are
					 in pairs, so the count is actually half this....  Handle much more carefully
					 kthnxbai */
				/* Note: check lengths match first, the later comparisons assume these already match */

				(fp_packet->ciphersuite_length == fp_nav->ciphersuite_length) &&
				(fp_packet->compression_length == fp_nav->compression_length) &&
				(fp_packet->extensions_length == fp_nav->extensions_length) &&
				(fp_packet->curves_length == fp_nav->curves_length) &&
				(fp_packet->sig_alg_length == fp_nav->sig_alg_length) &&
				(fp_packet->ec_point_fmt_length == fp_nav->ec_point_fmt_length) &&

				!(bcmp(fp_packet->ciphersuite, fp_nav->ciphersuite, fp_nav->ciphersuite_length)) &&
				!(bcmp(fp_packet->compression, fp_nav->compression, fp_nav->compression_length)) &&
				!(bcmp(fp_packet->extensions, fp_nav->extensions, fp_nav->extensions_length)) &&
				!(bcmp(realcurves, fp_nav->curves, fp_nav->curves_length)) &&
				!(bcmp(realsig_alg, fp_nav->sig_alg, fp_nav->sig_alg_length)) &&
				!(bcmp(realec_point_fmt, fp_nav->ec_point_fmt, fp_nav->ec_point_fmt_length))) {

					/* Whole criteria match.... woo! */
					matchcount++;
					/*
					fprintf(stdout, "[%s] Fingerprint Matched: \"%.*s\" %s connection from %s:%i to ", printable_time, fp_nav->desc_length ,fp_nav->desc, ssl_version(fp_nav->tls_version),
						src_address_buffer, ntohs(tcp->th_sport));
					fprintf(stdout, "%s:%i ", dst_address_buffer, ntohs(tcp->th_dport));
					fprintf(stdout, "Servername: \"");
					if(server_name != NULL) {
						for (arse = 7 ; arse <= (server_name[0]*256 + server_name[1]) + 1 ; arse++) {
							if (server_name[arse] > 0x20 && server_name[arse] < 0x7b)
								fprintf(stdout, "%c", server_name[arse]);
						}
					} else {
						fprintf(stdout, "Not Set");
					}
					fprintf(stdout, "\"");
					if(matchcount > 1)
						fprintf(stdout, "(Multiple Match)");
					fprintf(stdout, "\n");
					*/
					/*
					 * New output format.  JSON to allow easier automated parsing.
					 */
					 fprintf(log_fd, "{ "); // May need more header to define type?
					 fprintf(log_fd, "\"timestamp\": \"%s\", ", printable_time);
					 fprintf(log_fd, "\"event\": \"fingerprint_match\", ");

					 fprintf(log_fd, "\"ip_version\": ");
					 switch(ip_version) {
						 case 4:
						 	/* IPv4 */
							fprintf(log_fd, "\"ipv4\", ");
							inet_ntop(AF_INET,(void*)&ipv4->ip_src,src_address_buffer,sizeof(src_address_buffer));
							inet_ntop(AF_INET,(void*)&ipv4->ip_dst,dst_address_buffer,sizeof(dst_address_buffer));
							fprintf(log_fd, "\"ipv4_src\": \"%s\", ", src_address_buffer);
							fprintf(log_fd, "\"ipv4_dst\": \"%s\", ", dst_address_buffer);

							fprintf(log_fd, "\"src_port\": %hu, ", ntohs(tcp->th_sport));
							fprintf(log_fd, "\"dst_port\": %hu, ", ntohs(tcp->th_dport));

							break;
						 case 6:
						 	/* IPv6 */
							fprintf(log_fd, "\"ipv6\", ");
							inet_ntop(AF_INET6,(void*)&ipv6->ip6_src,src_address_buffer,sizeof(src_address_buffer));
							inet_ntop(AF_INET6,(void*)&ipv6->ip6_dst,dst_address_buffer,sizeof(dst_address_buffer));
							fprintf(log_fd, "\"ipv6_src\": \"%s\", ", src_address_buffer);
							fprintf(log_fd, "\"ipv6_dst\": \"%s\", ", dst_address_buffer);

							fprintf(log_fd, "\"src_port\": %hu, ", ntohs(tcp->th_sport));
							fprintf(log_fd, "\"dst_port\": %hu, ", ntohs(tcp->th_dport));
							break;
						 case 7:
						 	/*
							 * Teredo.  As this is an IPv6 within IPv4 tunnel, both sets of address are logged.
							 * The field names remain the same for ease of reporting on "all traffic from X" type
							 * scenarios, however the "ip_version" field makes it clear that this is an encapsulted
							 * tunnel.
							 */
							fprintf(log_fd, "\"teredo\", ");
							inet_ntop(AF_INET,(void*)&ipv4->ip_src,src_address_buffer,sizeof(src_address_buffer));
							inet_ntop(AF_INET,(void*)&ipv4->ip_dst,dst_address_buffer,sizeof(dst_address_buffer));
							fprintf(log_fd, "\"ipv4_src\": \"%s\", ", src_address_buffer);
							fprintf(log_fd, "\"ipv4_dst\": \"%s\", ", dst_address_buffer);
							inet_ntop(AF_INET6,(void*)&ipv6->ip6_src,src_address_buffer,sizeof(src_address_buffer));
							inet_ntop(AF_INET6,(void*)&ipv6->ip6_dst,dst_address_buffer,sizeof(dst_address_buffer));
							fprintf(log_fd, "\"ipv6_src\": \"%s\", ", src_address_buffer);
							fprintf(log_fd, "\"ipv6_dst\": \"%s\", ", dst_address_buffer);

							fprintf(log_fd, "\"src_port\": %hu, ", ntohs(tcp->th_sport));
							fprintf(log_fd, "\"dst_port\": %hu, ", ntohs(tcp->th_dport));

							/* Add in ports of the outer Teredo tunnel? */

							break;
						 case 8:
						 	/*
							 * 6in4. 	As this is an IPv6 within IPv4 tunnel, both sets of address are logged.
							 * The field names remain the same for ease of reporting on "all traffic from X" type
							 * scenarios, however the "ip_version" field makes it clear that this is an encapsulted
							 * tunnel.
							 */
							fprintf(log_fd, "\"6in4\", ");
							inet_ntop(AF_INET,(void*)&ipv4->ip_src,src_address_buffer,sizeof(src_address_buffer));
							inet_ntop(AF_INET,(void*)&ipv4->ip_dst,dst_address_buffer,sizeof(dst_address_buffer));
							fprintf(log_fd, "\"ipv4_src\": \"%s\", ", src_address_buffer);
							fprintf(log_fd, "\"ipv4_dst\": \"%s\", ", dst_address_buffer);
							inet_ntop(AF_INET6,(void*)&ipv6->ip6_src,src_address_buffer,sizeof(src_address_buffer));
							inet_ntop(AF_INET6,(void*)&ipv6->ip6_dst,dst_address_buffer,sizeof(dst_address_buffer));
							fprintf(log_fd, "\"ipv6_src\": \"%s\", ", src_address_buffer);
							fprintf(log_fd, "\"ipv6_dst\": \"%s\", ", dst_address_buffer);

							fprintf(log_fd, "\"src_port\": %hu, ", ntohs(tcp->th_sport));
							fprintf(log_fd, "\"dst_port\": %hu, ", ntohs(tcp->th_dport));
							break;
					 }

					 fprintf(log_fd, "\"tls_version\": \"%s\", ", ssl_version(fp_nav->tls_version));
					 fprintf(log_fd, "\"fingerprint_desc\": \"%.*s\", ", fp_nav->desc_length, fp_nav->desc);

					 fprintf(log_fd, "\"server_name\": \"");

					 if(server_name != NULL) {
 						for (arse = 7 ; arse <= (server_name[0]*256 + server_name[1]) + 1 ; arse++) {
 							if (server_name[arse] > 0x20 && server_name[arse] < 0x7b)
 								fprintf(log_fd, "%c", server_name[arse]);
 						}
 					}

					fprintf(log_fd, "\" }\n");

			} else {
				// Fuzzy Match goes here (if we ever want it)

			}

		}

		/* ********************************************* */


		if(matchcount == 0) {
			/* Write to unknown fingerprint pcap file (if opened already) */
//			if(output_handle != NULL) {
				//pcap_dump(output_handle, pcap_header, packet);
//			}



			/*
				OK, we're setting up a signature, let's  actually do some memory fun
			*/
			uint8_t *temp;

			/* Update pointer for next to the top of list */
			fp_packet->next = search[((fp_packet->ciphersuite_length & 0x000F) >> 1 )][((fp_packet->tls_version) & 0x00FF)];

			/* Populate the fingerprint */
			fp_packet->fingerprint_id = 0;
			fp_packet->desc_length = strlen("Dynamic ") + strlen(hostname) + 7; // 7 should cover the max uint16_t + space
			fp_packet->desc = malloc(fp_packet->desc_length);

			if(fp_packet->desc == NULL) {
				printf("Malloc Error (desc)\n");
				exit(0);
			}
			sprintf(fp_packet->desc, "Dynamic %s %d", hostname, newsig_count);


			fp_packet->sig_alg = malloc(fp_packet->sig_alg_length);
			if(fp_packet->sig_alg == NULL) {
				printf("Malloc Error (sig_alg)\n");
				exit(0);
			}

			fp_packet->ec_point_fmt = malloc(fp_packet->ec_point_fmt_length);
			if(fp_packet->ec_point_fmt == NULL) {
				printf("Malloc Error (ec_point_fmt)\n");
				exit(0);
			}

			fp_packet->curves = malloc(fp_packet->curves_length);
			if(fp_packet->curves == NULL) {
				printf("Malloc Error (curves)\n");
				exit(0);
			}

			temp = fp_packet->ciphersuite;
			fp_packet->ciphersuite = malloc(fp_packet->ciphersuite_length);
			if(fp_packet->ciphersuite == NULL) {
				printf("Malloc Error (ciphersuites)\n");
				exit(0);
			}
			memcpy(fp_packet->ciphersuite, temp, fp_packet->ciphersuite_length);

			temp = fp_packet->compression;
			fp_packet->compression = malloc(fp_packet->compression_length);
			if(fp_packet->compression == NULL) {
				printf("Malloc Error (compression)\n");
				exit(0);
			}
			memcpy(fp_packet->compression, temp, fp_packet->compression_length);

			memcpy(fp_packet->curves, realcurves, fp_packet->curves_length);
			memcpy(fp_packet->sig_alg, realsig_alg, fp_packet->sig_alg_length);
			memcpy(fp_packet->ec_point_fmt, realec_point_fmt, fp_packet->ec_point_fmt_length);


			printf("[%s] New FingerPrint [%i] Detected, dynamically adding to in-memory fingerprint database\n", printable_time, newsig_count++);
			fp_nav = fp_packet;	// Temporarily just point one thing to another for testing.


			/*
				Insert fingerprint as first in it's "list"
			*/
			search[((fp_packet->ciphersuite_length & 0x000F) >> 1 )][((fp_packet->tls_version) & 0x00FF)] = fp_packet;


			/* If selected output in the normal stream */

			printf("[%s] New Fingerprint \"%s\": %s connection from %s:%i to ", printable_time, fp_nav->desc, ssl_version(fp_packet->tls_version),
				src_address_buffer, ntohs(tcp->th_sport));
			printf("%s:%i ", dst_address_buffer, ntohs(tcp->th_dport));
			printf("Servername: \"");
			if(server_name != NULL) {
				for (arse = 7 ; arse <= (server_name[0]*256 + server_name[1]) + 1 ; arse++) {
					if (server_name[arse] > 0x20 && server_name[arse] < 0x7b)
						printf("%c", server_name[arse]);
				}
			} else {
				printf("Not Set");
			}
			printf("\"\n");

			// Should just for json_fd being /dev/null and skip .. optimisation...
			// or make an output function linked list XXX
			fprintf(json_fd, "{\"id\": %i, \"desc\": \"", fp_packet->fingerprint_id);
			fprintf(json_fd, "%s\", ", fp_packet->desc);
			fprintf(json_fd, "\"record_tls_version\": \"0x%.04X\", ", fp_packet->record_tls_version);
			fprintf(json_fd, "\"tls_version\": \"0x%.04X\", \"ciphersuite_length\": \"0x%.04X\", ",
				fp_packet->tls_version, fp_packet->ciphersuite_length);

			fprintf(json_fd, "\"ciphersuite\": \"");
			for (arse = 0; arse < fp_packet->ciphersuite_length; ) {
				fprintf(json_fd, "0x%.02X%.02X", (uint8_t) fp_packet->ciphersuite[arse], (uint8_t) fp_packet->ciphersuite[arse+1]);
				arse = arse + 2;
				if(arse + 1 < fp_packet->ciphersuite_length)
					fprintf(json_fd, " ");
			}
			fprintf(json_fd, "\", ");



			fprintf(json_fd, "\"compression_length\": \"%i\", ",
				fp_packet->compression_length);

			fprintf(json_fd, " \"compression\": \"");
			if (fp_packet->compression_length == 1) {
				fprintf(json_fd, "0x%.02X", (uint8_t) fp_packet->compression[0]);
			} else {
				for (arse = 0; arse < fp_packet->compression_length; ) {
					fprintf(json_fd, "0x%.02X", (uint8_t) fp_packet->compression[arse]);
					arse++;
					if(arse < fp_packet->compression_length)
						fprintf(json_fd, " ");
				}
			}

			fprintf(json_fd, "\", ");


			fprintf(json_fd, "\"extensions\": \"");
			for (arse = 0 ; arse < fp_packet->extensions_length ;) {
				fprintf(json_fd, "0x%.02X%.02X", (uint8_t) fp_packet->extensions[arse], (uint8_t) fp_packet->extensions[arse+1]);
				arse = arse + 2;
				if(arse < ext_len -1)
					fprintf(json_fd, " ");
			}
			fprintf(json_fd, "\"");

			if(fp_packet->curves != NULL) {
				fprintf(json_fd, ", \"e_curves\": \"");

				for (arse = 0 ; arse < fp_packet->curves_length &&
					fp_packet->curves_length > 0 ; arse = arse + 2) {

					fprintf(json_fd, "0x%.2X%.2X", fp_packet->curves[arse], fp_packet->curves[arse+1]);
					if ((arse + 1) < fp_packet->curves_length) {
						fprintf(json_fd, " ");
					}
				}
				fprintf(json_fd, "\"");
			}

			if(fp_packet->sig_alg != NULL) {
				fprintf(json_fd, ", \"sig_alg\": \"");

				for (arse = 0 ; arse < (fp_packet->sig_alg_length) &&
					fp_packet->sig_alg_length > 0 ; arse = arse + 2) {

					fprintf(json_fd, "0x%.2X%.2X", fp_packet->sig_alg[arse], fp_packet->sig_alg[arse+1]);
					if ((arse + 1) < (fp_packet->sig_alg_length)) {
						fprintf(json_fd, " ");
					}
				}
				fprintf(json_fd, "\"");
			}

			if(fp_packet->ec_point_fmt != NULL) {
				fprintf(json_fd, ", \"ec_point_fmt\": \"");

				// Jumping to "3" to get past the second length parameter... errrr... why?
				for (arse = 0 ; arse < fp_packet->ec_point_fmt_length; arse++) {
					fprintf(json_fd, "0x%.2X", fp_packet->ec_point_fmt[arse]);
					if ((arse + 1) < fp_packet->ec_point_fmt_length) {
						fprintf(json_fd, " ");
					}
				}
				fprintf(json_fd, "\"");
			}

			if(server_name != NULL) {
				fprintf(json_fd, ", \"server_name\": \"");
				for (arse = 7 ; arse <= (server_name[0]*256 + server_name[1]) + 1 ; arse++) {
					if (server_name[arse] > 0x20 && server_name[arse] < 0x7b)
						fprintf(json_fd, "%c", server_name[arse]);
					else
						fprintf(json_fd, "*");
				}
				fprintf(json_fd, "\"");
			}

			fprintf(json_fd, "}\n");
			/* **************************** */
			/* END OF RECORD - OR SOMETHING */
			/* **************************** */

			/* Write the sample packet out */
			if(output_handle != NULL) {
				pcap_dump((u_char *)output_handle, pcap_header, packet);
			}

			/*
				Setup the new fp_packet for the next incoming packet.  Next call to this function will cause a malloc.
			*/
			fp_packet = NULL;
			extensions_malloc = 0;

		} else {

		}

}
