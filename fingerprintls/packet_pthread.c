/*
 * Queue packets into the appropriate buffer for the pthread that will handle it
 */

 // XXX Currently not happening!
//void packet_queue_handler(u_char *args, const struct pcap_pkthdr *pcap_header, const u_char *packet) {
//
//	/* Quick and dirty, just throw the whole thing into a pthread */
//	//extern struct pthread_config *my_thread_config;
//
//	/* Copy things to new locations */
//	// If the thread mutex cannot be obtained it's processing a packet
//	// Check status flag to avoid a condition where there is no lock but thread is not ready for a new packet.
//	//while(my_thread_config->status != 0) {
//	//	printf("Oh noes, no status\n");
//	//}
//
//
//	for( ; ((pthread_mutex_trylock(&my_thread_config->mutex) != 0) && my_thread_config->status == 1) ;  my_thread_config = my_thread_config->next) {
//		// If needed a nanosleep here can be used to save thrashing the CPU looking for free threads
//	}
//
//	//if((pthread_mutex_trylock(&my_thread_config->mutex) != 0) && my_thread_config->status == 1) {
//	//	printf("Debug: Thread #%i not ready\n", my_thread_config->threadnum);
//
//		// XXX deal with here
//	//} else {
//		// Got a lock (in the if), so yay it's free, let's compute...
//		memcpy(my_thread_config->pcap_header, pcap_header, sizeof(&pcap_header));
//		memcpy(my_thread_config->packet, packet, pcap_header->len);
//		my_thread_config->status = 1;  // Set flag for thread to pickup packet
//		pthread_mutex_unlock(&my_thread_config->mutex); // Mutex is unlocked, the thread will process.
//		/* Move the pointer on to the next thread ready for the next packet */
//		my_thread_config = my_thread_config->next;
//	//}
//
//}

//void copy_packet(u_char *args, struct pcap_pkthdr *pcap_header, u_char *packet) {
//
//	struct pcap_pkthdr *pcap_header_copy;
//  u_char *packet_copy;
//
//	extern pthread_mutex_t log_mutex;
//	extern pthread_mutex_t json_mutex;
//	extern pthread_mutex_t pcap_mutex;
//	extern pthread_mutex_t fpdb_mutex;
//
//	/* If this works assign once and use pointers */
//	pcap_header_copy = calloc(1, sizeof(struct pcap_pkthdr));
//	packet_copy = calloc(1, SNAP_LEN);
//
//	memcpy(pcap_header_copy, pcap_header, sizeof(&pcap_header));
//	memcpy(packet_copy, packet, pcap_header->len);
//
//	/*
//		We can do this because although a different function, this is the same thread that locked the pcap interface
//		This Frees up the next thread to grab a packet as we have already taken a copy and no longer need to refer
//		to the one provided by libpcap.
//	*/
//	pthread_mutex_unlock(&pcap_mutex);
//
//	/* Now we have copied the packet, we can process it whilst other threads do their thing */
//	got_packet((u_char *) NULL, pcap_header_copy, packet_copy);
//
//	free(pcap_header_copy);
//	free(packet_copy);
//}


void got_packet(u_char *args, const struct pcap_pkthdr *pcap_header, const u_char *packet) {
		/* ************************************************************************* */
		/* Variables, gotta have variables, and structs and pointers....  and things */
		/* ************************************************************************* */

		extern FILE *json_fd;
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

		struct fingerprint_new *fp_current;			/* For navigating the fingerprint database */
		struct fingerprint_new *fp_temp;			/* Generated fingerprint for incoming packet */

		/* pointers to key places in the packet headers */
		struct ether_header *ethernet;	/* The ethernet header [1] */
		struct ipv4_header *ipv4;         /* The IPv4 header */
		struct ip6_hdr *ipv6;             /* The IPv6 header */
		struct tcp_header *tcp;           /* The TCP header */
		u_char *payload;                  /* Packet payload */

		/* Different to struct fingerprint in fpdb.h, this is for building new fingerprints */
		struct tmp_fingerprint {
			uint16_t 	id;
			char 			desc[312];
//			uint16_t 	record_tls_version;
//			uint16_t 	tls_version;
//			uint16_t 	ciphersuite_length;
//			uint8_t		*ciphersuite;
//			uint8_t		compression_length;
//			uint8_t		*compression;
//			uint16_t 	extensions_length;
			uint8_t		*extensions;
//			uint16_t	e_curves_length;
			uint8_t		*e_curves;
//			uint16_t 	sig_alg_length;
			uint8_t		*sig_alg;
//			uint16_t 	ec_point_fmt_length;
			uint8_t		*ec_point_fmt;
			char 			*server_name;
			int				padding_length;
		} packet_fp;



		fp_temp = malloc(sizeof(struct fingerprint_new));
		if(fp_temp == NULL) {
			printf("Malloc Error\n");
			exit(0);
		}

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
			if(show_drops) {
				fprintf(stderr, "[%s] Packet Passed header length: %u bytes\n", printable_time, size_ip);
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
				printf("[%s] Packet Drop: Session ID looks bad [%i] [%i]\n", printable_time, size_payload, (OFFSET_SESSION_LENGTH + cipher_data[0] + 3) );
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
		fp_temp->record_tls_version = (payload[1]*256) + payload[2];

		/* TLS Version */
		fp_temp->tls_version = (payload[OFFSET_HELLO_VERSION]*256) + payload[OFFSET_HELLO_VERSION+1];

		/* CipherSuite */
		cipher_data += 1 + cipher_data[0];
		u_short cs_len = cipher_data[0]*256 + cipher_data[1];
		/* Length */
		fp_temp->ciphersuite_length = (cipher_data[0]*256) + cipher_data[1];


		/* CipherSuites */
		cipher_data += 2; // skip cipher suites length

		fp_temp->ciphersuite = malloc(fp_temp->ciphersuite_length);
		if(fp_temp->ciphersuite == NULL) {
			printf("Malloc Error\n");
			exit(0);
		}
		memcpy(fp_temp->ciphersuite, (uint8_t *)cipher_data, fp_temp->ciphersuite_length);
		//packet_fp.ciphersuite = (uint8_t *)cipher_data;

		/* Compression */
		u_short comp_len = cipher_data[cs_len];

		/* Length */
		fp_temp->compression_length = comp_len;

		/* Compression List */
		cipher_data += cs_len + 1;

		fp_temp->compression = malloc(fp_temp->compression_length);
		if(fp_temp->compression == NULL) {
			printf("Malloc Error\n");
			exit(0);
		}
		memcpy(fp_temp->compression, (uint8_t *)cipher_data, fp_temp->compression_length);
		//packet_fp.compression = (uint8_t *)cipher_data;
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
		fp_temp->extensions_length = 0;
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
					fp_temp->curves_length = packet_fp.e_curves[2]*256 + packet_fp.e_curves[3];
					break;
				case 0x000b:
					/* ec_point formats */
					packet_fp.ec_point_fmt = (uint8_t *)&cipher_data[ext_id + 2];
					fp_temp->ec_point_fmt_length = packet_fp.ec_point_fmt[2];
					break;
				case 0x000d:
					/* Signature algorithms */
					packet_fp.sig_alg = (uint8_t *)&cipher_data[ext_id + 2];
					fp_temp->sig_alg_length = packet_fp.sig_alg[2]*256 + packet_fp.sig_alg[3];
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
			fp_temp->extensions_length = (ext_count * 2);

			/* Increment past the payload of the extensions */
			ext_id += (cipher_data[ext_id + 2]*256) + cipher_data[ext_id + 3] + 3;

		}



	//	int fp_loop, arse;


		/* XXX This horrible kludge to get around the 2 length fields.  FIX IT! */
		// XXX Check that curves are working (being matched, etc)
		uint8_t *realcurves = packet_fp.e_curves;
		if (packet_fp.e_curves != NULL) {
			realcurves += 4;
		} else {
			realcurves = NULL;
			fp_temp->curves_length = 0;
		}
			/* ******************************************************************** */

		/* XXX This horrible kludge to get around the 2 length fields.  FIX IT! */
		uint8_t *realsig_alg = packet_fp.sig_alg;
			if(packet_fp.sig_alg != NULL) {
			realsig_alg += 4;
		} else {
			realsig_alg = NULL;
			fp_temp->sig_alg_length = 0;
		}
		/* ******************************************************************** */

		/* XXX This horrible kludge to get around the 2 length fields.  FIX IT! */
		uint8_t *realec_point_fmt = packet_fp.ec_point_fmt;
		if(packet_fp.ec_point_fmt != NULL) {
			realec_point_fmt += 3;
		} else {
			realec_point_fmt = NULL;
			fp_temp->ec_point_fmt_length = 0;
		}
		/* ******************************************************************** */

		/*
			This is only living here temporarily (XXX).  This is to test that this setup works in principle,
			before merging into main it will need to be merged with above to remove duplication of work.

			We will create a fingerprint upfront, create a new thread, that will match new against DB then either
			call free (or reuse) or shuffle pointers to place it in the database.

			Other changes will happen, like switching malloc for calloc, checking the calloc call, etc
		*/
		// XXX Should really check if malloc works ;)
		/* Update pointer for next to the top of list */
		fp_temp->next = search[((fp_temp->ciphersuite_length & 0x000F) >> 1 )][((fp_temp->tls_version) & 0x00FF)];
		/* Populate the fingerprint */
		fp_temp->fingerprint_id = 0;
		fp_temp->desc_length = strlen("Dynamic ") + strlen(hostname) + 7; // 7 should cover the max uint16_t + space
		fp_temp->desc = malloc(fp_temp->desc_length);
		if(fp_temp->desc == NULL) {
			printf("Malloc Error\n");
			exit(0);
		}
		sprintf(fp_temp->desc, "Dynamic %s %d", hostname, newsig_count);
		//fp_temp->record_tls_version = packet_fp.record_tls_version;
		//fp_temp->tls_version = packet_fp.tls_version;
		//fp_temp->ciphersuite_length = packet_fp.ciphersuite_length;
		//fp_temp->compression_length = packet_fp.compression_length; // Actually *IS* a uint8_t field!!!  ZOMG
		//fp_temp->extensions_length = (ext_count * 2);
		//fp_temp->curves_length = packet_fp.e_curves_length;
		//fp_temp->sig_alg_length = packet_fp.sig_alg_length;
		//fp_temp->ec_point_fmt_length = packet_fp.ec_point_fmt_length;
		// XXX This little malloc fest should be rolled into one.
		//fp_temp->ciphersuite = malloc(fp_temp->ciphersuite_length);
		//fp_temp->compression = malloc(fp_temp->compression_length);
		fp_temp->extensions = malloc(fp_temp->extensions_length);
		if(fp_temp->extensions == NULL) {
			printf("Malloc Error\n");
			exit(0);
		}
		//fp_temp->curves = malloc(fp_temp->curves_length);
		fp_temp->sig_alg = malloc(fp_temp->sig_alg_length);
		if(fp_temp->sig_alg == NULL) {
			printf("Malloc Error\n");
			exit(0);
		}
		fp_temp->ec_point_fmt = malloc(fp_temp->ec_point_fmt_length);
		if(fp_temp->ec_point_fmt == NULL) {
			printf("Malloc Error\n");
			exit(0);
		}
		// Copy the data over (except extensions)
		//memcpy(fp_temp->ciphersuite, packet_fp.ciphersuite, fp_temp->ciphersuite_length);
		//memcpy(fp_temp->compression, packet_fp.compression, fp_temp->compression_length);
		fp_temp->curves = malloc(fp_temp->curves_length);
		if(fp_temp->curves == NULL) {
			printf("Malloc Error\n");
			exit(0);
		}
		memcpy(fp_temp->curves, realcurves, fp_temp->curves_length);

		memcpy(fp_temp->sig_alg, realsig_alg, fp_temp->sig_alg_length);
		memcpy(fp_temp->ec_point_fmt, realec_point_fmt, fp_temp->ec_point_fmt_length);

		// Load up the extensions
		int unarse = 0;
		for (arse = 0 ; arse < ext_len ;) {
			fp_temp->extensions[unarse] = (uint8_t) packet_fp.extensions[arse];
			fp_temp->extensions[unarse+1] = (uint8_t) packet_fp.extensions[arse+1];
			unarse += 2;
			arse = arse + 4 + (packet_fp.extensions[(arse+2)]*256) + (packet_fp.extensions[arse+3]);
		}

		/*
			XXX End of temp stuff XXX
			XXX End of temp stuff XXX
			XXX End of temp stuff XXX
		*/

		/* ********************************************* */
		/* The "compare to the fingerprint database" bit */
		/* ********************************************* */


		int matchcount = 0;

		/* ************************* */
		/* New Matching thinger test */
		/* ************************* */
		//for(fp_current = fp_first ; fp_current != NULL; fp_current = fp_current->next) {


		// XXX pass this to a new thread and return the function so that the next packet and be parsed

		for(fp_current = search[((fp_temp->ciphersuite_length & 0x000F) >> 1 )][((fp_temp->tls_version) & 0x00FF)] ;
			fp_current != NULL; fp_current = fp_current->next) {

			// XXX Need to optimise order and remove duplicate checks already used during indexing.
			if ((fp_temp->record_tls_version == fp_current->record_tls_version) &&
				(fp_temp->tls_version == fp_current->tls_version) &&
				/* XXX extensions_length is misleading!  Length is variable, it is a count of
				   uint8_t's that makes the extensions _list_.  Furthermore, these values are
					 in pairs, so the count is actually half this....  Handle much more carefully
					 kthnxbai */
				/* Note: check lengths match first, the later comparisons assume these already match */

				// XXX Crash when reading a new fingerprint as a recognised one

				(fp_temp->ciphersuite_length == fp_current->ciphersuite_length) &&
				(fp_temp->compression_length == fp_current->compression_length) &&
				(fp_temp->extensions_length == fp_current->extensions_length) &&
				(fp_temp->curves_length == fp_current->curves_length) &&
				(fp_temp->sig_alg_length == fp_current->sig_alg_length) &&
				(fp_temp->ec_point_fmt_length == fp_current->ec_point_fmt_length) &&

				!(bcmp(fp_temp->ciphersuite, fp_current->ciphersuite, fp_current->ciphersuite_length)) &&
				!(bcmp(fp_temp->compression, fp_current->compression, fp_current->compression_length)) &&
				!(bcmp(fp_temp->extensions, fp_current->extensions, fp_current->extensions_length)) &&
				!(bcmp(realcurves, fp_current->curves, fp_current->curves_length)) &&
				!(bcmp(fp_temp->sig_alg, fp_current->sig_alg, fp_current->sig_alg_length)) &&
				!(bcmp(fp_temp->ec_point_fmt, fp_current->ec_point_fmt, fp_current->ec_point_fmt_length))) {
					/* Whole criteria match.... woo! */
					matchcount++;
					fprintf(stdout, "[%s] Fingerprint Matched: \"%.*s\" %s connection from %s:%i to ", printable_time, fp_current->desc_length ,fp_current->desc, ssl_version(fp_current->tls_version),
						src_address_buffer, ntohs(tcp->th_sport));
					fprintf(stdout, "%s:%i ", dst_address_buffer, ntohs(tcp->th_dport));
					fprintf(stdout, "Servername: \"");
					if(packet_fp.server_name != NULL) {
						for (arse = 7 ; arse <= (packet_fp.server_name[0]*256 + packet_fp.server_name[1]) + 1 ; arse++) {
							if (packet_fp.server_name[arse] > 0x20 && packet_fp.server_name[arse] < 0x7b)
								fprintf(stdout, "%c", packet_fp.server_name[arse]);
						}
					} else {
						fprintf(stdout, "Not Set");
					}
					fprintf(stdout, "\"");

					if(matchcount > 1)
						/* This shouldn't happen, but is useful to debug duplicate fingerprints */

						/* May disable this for speed optimisation (or make it configurable) */

						fprintf(stdout, "(Multiple Match)");
					fprintf(stdout, "\n");
			} else {
				// Fuzzy Match goes here (if we ever want it)
			}
		}


		/* ********************************************* */


		if(matchcount == 0) {
			newsig_count++;

			printf("[%s] New FingerPrint [%i] Detected, dynamically adding to in-memory fingerprint database\n", printable_time, newsig_count);

			fp_current = fp_temp;	// Temporarily just point one thing to another for testing.


			/* Finally, insert this into the list */
			search[((fp_temp->ciphersuite_length & 0x000F) >> 1 )][((fp_temp->tls_version) & 0x00FF)] = fp_current;


			/* If selected output in the normal stream */

			printf("[%s] New Fingerprint \"%s\": %s connection from %s:%i to ", printable_time, fp_current->desc, ssl_version(fp_temp->tls_version),
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
			fprintf(json_fd, "\"record_tls_version\": \"0x%.04X\", ", fp_temp->record_tls_version);
			fprintf(json_fd, "\"tls_version\": \"0x%.04X\", \"ciphersuite_length\": \"0x%.04X\", ",
				fp_temp->tls_version, fp_temp->ciphersuite_length);

			fprintf(json_fd, "\"ciphersuite\": \"");
			for (arse = 0; arse < fp_temp->ciphersuite_length; ) {
				fprintf(json_fd, "0x%.02X%.02X", (uint8_t) fp_temp->ciphersuite[arse], (uint8_t) fp_temp->ciphersuite[arse+1]);
				arse = arse + 2;
				if(arse + 1 < fp_temp->ciphersuite_length)
					fprintf(json_fd, " ");
			}
			fprintf(json_fd, "\", ");



			fprintf(json_fd, "\"compression_length\": \"%i\", ",
				fp_temp->compression_length);

			fprintf(json_fd, " \"compression\": \"");
			if (fp_temp->compression_length == 1) {
				fprintf(json_fd, "0x%.02X", (uint8_t) fp_temp->compression[0]);
			} else {
				for (arse = 0; arse < fp_temp->compression_length; ) {
					fprintf(json_fd, "0x%.02X", (uint8_t) fp_temp->compression[arse]);
					arse++;
					if(arse < fp_temp->compression_length)
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
		} else {
			/*
				It is matched and so we do not need this memory allocation anymore.
				Time to free to things
			*/

			free(fp_temp->ciphersuite);
			free(fp_temp->compression);
			free(fp_temp->desc);
			free(fp_temp->extensions);
			free(fp_temp->sig_alg);
			free(fp_temp->ec_point_fmt);
			free(fp_temp);
		}

}
