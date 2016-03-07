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
// XXX Add UDP support (not as easy as I thought, DTLS has differences... still add it though)
// XXX enhance search to include sorting per list/thread/shard/thingy
// XXX add 6in4 support (should be as simple as UDP and IPv6... in theory)
// XXX add Teredo support



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

/* Stuff to process packets */
#include "packet_processing.c"


/*
 * print help text
 */
void print_usage(char *bin_name) {
	fprintf(stderr, "Usage: %s <options>\n\n", bin_name);
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "    -h                This message\n");
	fprintf(stderr, "    -i <interface>    Sniff packets from specified interface\n");
	fprintf(stderr, "    -p <pcap file>    Read packets from specified pcap file\n");
	fprintf(stderr, "    -P <pcap file>    Save packets to specified pcap file for unknown fingerprints\n");
	fprintf(stderr, "    -j <json file>    Output JSON fingerprints\n");
	fprintf(stderr, "    -l <log file>     Output logfile (JSON format)\n");
//	fprintf(stderr, "    -s                Output JSON signatures of unknown connections to stdout\n");  // Comment this out as I'm trying to deprecate this
	fprintf(stderr, "    -d                Show reasons for discarded packets (post BPF)\n");
	fprintf(stderr, "    -f <fpdb>         Load the (binary) FingerPrint Database\n");
	fprintf(stderr, "    -u <uid>          Drop privileges to specified UID (not username)\n");
	fprintf(stderr, "\n");
	return;
}

/* Testing another way of searching the in memory database */
uint shard_fp (struct fingerprint_new *fp_lookup, uint16_t maxshard) {
				return (((fp_lookup->ciphersuite_length) + (fp_lookup->tls_version)) & (maxshard -1));
}

int main(int argc, char **argv) {

	char *dev = NULL;											/* capture device name */
	char *unpriv_user = NULL;							/* User for dropping privs */
	char errbuf[PCAP_ERRBUF_SIZE];				/* error buffer */
	extern pcap_t *handle;								/* packet capture handle */
	extern pcap_dumper_t *output_handle;					/* output to pcap handle */

	char *filter_exp = default_filter;
	int arg_start = 1, i;
	extern struct bpf_program fp;					/* compiled filter program (expression) */

	extern FILE *json_fd, *fpdb_fd, *log_fd;
	int filesize;
	uint8_t *fpdb_raw = NULL;
	int	fp_count = 0;
	extern int show_drops;
	extern char hostname[HOST_NAME_MAX];
	show_drops = 0;


	/* Make sure pipe sees new packets unbuffered. */
	//setvbuf(stdout, (char *)NULL, _IOLBF, 0);
	setlinebuf(stdout);

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
			case 'P':
				/* Open the file */
				output_handle = pcap_dump_open(pcap_open_dead(DLT_EN10MB, 65535), argv[++i]);
				if (output_handle != NULL) {
					printf("Writing samples to file: %s\n", argv[i]);
				} else {
					printf("Could not save samples: %s\n", errbuf);
					exit(-1);
				}
				break;
			case 'i':
				/* Open the interface */
				/* Check if file already successfully opened, if bad filename we can fail to sniffing */
				if (handle != NULL) {
					printf("-p and -i are mutually exclusive\n");
					exit(-1);
				}
				handle = pcap_open_live(argv[++i], SNAP_LEN, 1, 1000, errbuf);
				printf("Using interface: \033[1;36m%s\033[1;m\n", argv[i]);
				break;
			case 'j':
				/* JSON output to file */
				if((json_fd = fopen(argv[++i], "a")) == NULL) {
					printf("Cannot open JSON file for output\n");
					exit(-1);
				}
				// Buffering is fine, but linebuf needed for tailers to work properly
				setlinebuf(json_fd);
				break;
			case 'l':
				/* Output to log file */
				if((log_fd = fopen(argv[++i], "a")) == NULL) {
					printf("Cannot open log file for output\n");
					exit(-1);
				}
				// Buffering is fine, but linebuf needed for tailers to work properly
				setlinebuf(log_fd);
				break;
			case 's':
				/* JSON output to stdout */
				if((json_fd = fopen("/dev/stdout", "a")) == NULL) {
					printf("Cannot open JSON file for output\n");
					fprintf(json_fd, "FD TEST\n");
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
		fp_current->next = search[((fp_current->ciphersuite_length & 0x000F) >> 1 )][((fp_current->tls_version) & 0x00FF)];
		search[((fp_current->ciphersuite_length & 0x000F) >> 1 )][((fp_current->tls_version) & 0x00FF)] = fp_current;
	}

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

	/* setup hostname variable for use in logs (incase of multiple hosts) */
	if(gethostname(hostname, HOST_NAME_MAX) != 0) {
		sprintf(hostname, "unknown");
	}

	/* now we can set our callback function */
	pcap_loop(handle, -1, got_packet, NULL);

	fprintf(stderr, "Reached end of pcap\n");

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	return 0;
}
