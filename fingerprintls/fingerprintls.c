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

// XXX pthread mutex's TODO
// 1 - Per thread queue (done - testing)
// 2 - Updates to in memory database - XXX NEEDS TO BE DONE!!
// 3 - Accesses to printf (done - testing)

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

/* Trying some POSIX Threads */
#include <pthread.h>

/* And my own signal handler functions */
#include "signal.c"

/* My own header sherbizzle */
#include "fingerprintls.h"

/* Stuff to process packets */
#include "packet_pthread.c"

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
	fprintf(stderr, "    -u <uid>          Drop privileges to specified UID (not username)\n");
//	fprintf(stderr, "    -t <count>        How many worker threads to use\n");
	fprintf(stderr, "\n");
	return;
}

void output() {

}

/*
 * Queue packets into the appropriate buffer for the pthread that will handle it
 */
void packet_queue_handler(u_char *args, const struct pcap_pkthdr *pcap_header, const u_char *packet) {

	/* Quick and dirty, just throw the whole thing into a pthread */
	//extern struct pthread_config *my_thread_config;

	/* Copy things to new locations */
	// If the thread mutex cannot be obtained it's processing a packet
	// Check status flag to avoid a condition where there is no lock but thread is not ready for a new packet.
	//while(my_thread_config->status != 0) {
	//	printf("Oh noes, no status\n");
	//}


	for( ; ((pthread_mutex_trylock(&my_thread_config->mutex) != 0) && my_thread_config->status == 1) ;  my_thread_config = my_thread_config->next) {
		// If needed a nanosleep here can be used to save thrashing the CPU looking for free threads
	}

	//if((pthread_mutex_trylock(&my_thread_config->mutex) != 0) && my_thread_config->status == 1) {
	//	printf("Debug: Thread #%i not ready\n", my_thread_config->threadnum);

		// XXX deal with here
	//} else {
		// Got a lock (in the if), so yay it's free, let's compute...
		memcpy(my_thread_config->pcap_header, pcap_header, sizeof(&pcap_header));
		memcpy(my_thread_config->packet, packet, pcap_header->len);
		my_thread_config->status = 1;  // Set flag for thread to pickup packet
		pthread_mutex_unlock(&my_thread_config->mutex); // Mutex is unlocked, the thread will process.
		/* Move the pointer on to the next thread ready for the next packet */
		my_thread_config = my_thread_config->next;
	//}

}

//  Need to work out local vs extern use of my_thread_config XXX ....  2 functions using it could cause thread issues

void *packet_pthread (void *thread_num) {
	int thread_counter;
	struct pthread_config *local_thread_config;

	/* Get "my" config (as opposed to other threads) before doing anything else */
	local_thread_config = pthread_config_ptr;
	for(thread_counter = 0 ; thread_counter < (int) thread_num ; thread_counter++)
		local_thread_config = local_thread_config->next;

	/* For this test, we'll just while loop it */
	while(1) {

		// Blocking mutex_lock should be enough to schedule readiness, but status is a double check because
		// I believe there is a chance of a race condition, so it's an extra check without CPU intensive fun
		if((pthread_mutex_lock(&local_thread_config->mutex) == 0) && local_thread_config->status == 1) {
			got_packet((u_char *) NULL, local_thread_config->pcap_header, local_thread_config->packet);
			local_thread_config->status = 0;
		}
	}

	/* Exit the pthread */
	pthread_exit(NULL);

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

	/* pthreads */
	extern pthread_t threads[THREAD_COUNT];
	long pt;


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

	/* Before we setup pthreads, get all the mutexs setup */
	extern pthread_mutex_t log_mutex;
	extern pthread_mutex_t json_mutex;
	extern pthread_mutex_t fpdb_mutex;

	pthread_mutex_init(&log_mutex, NULL);
	pthread_mutex_init(&json_mutex, NULL);
	pthread_mutex_init(&fpdb_mutex, NULL);

	/* Create pthread configs.  Doing this before spawning the threads in case it causes issues somehow */
	struct pthread_config *working_pthread_config;
	extern struct pthread_config *next_thread_config;
	my_thread_config = working_pthread_config = pthread_config_ptr = calloc(1, sizeof(struct pthread_config));
	for(x = 0; x < THREAD_COUNT; x++) {
		printf("setting up thread config #%i\n", x);
		/* Will need to make the size of buffer configurable in future, sticking with 10 packets for now */
		working_pthread_config->pcap_header = calloc(1, sizeof(struct pcap_pkthdr));
		working_pthread_config->packet = calloc(1, SNAP_LEN);
		working_pthread_config->status = 2;
		working_pthread_config->threadnum = x; // Aids debugging if we can tell which thread did what
		if(pthread_mutex_init(&working_pthread_config->mutex, NULL) != 0) {		// Setup mutex used for locking any one thread for packet queueing purposes
			printf("Failed to setup pthread mutexs\n");
			exit(0);
		} else {
			// Set the lock straight away so that the thread doesn't grab it before other things do
			pthread_mutex_lock(&working_pthread_config->mutex);
		}
		if(x < (THREAD_COUNT-1)) {
			//working_pthread_config->next = working_pthread_config + sizeof(struct pthread_config);
			//working_pthread_config = working_pthread_config->next;
			working_pthread_config->next = calloc(1, sizeof(struct pthread_config));
			working_pthread_config = working_pthread_config->next;
		} else {
			/* This is circular, so the packet quererer can just next, next, next, next the whole time
			   This way it needs to knowledge of how many, etc.  Something else could add them in and out
				 and reorder as necessary */
			working_pthread_config->next = pthread_config_ptr;
		}
		/* initialise the pthread mutex used for buffer management */
		/* pthread_cond_init(working_pthread_config->queue_empty, NULL); */
	}


	/* Create the threads, with their thread id thing */
	/* This way they are started before the packets start arriving in the buffer */
	for(x = 0; x < THREAD_COUNT; x++) {
		pt = pthread_create(&threads[x], NULL, packet_pthread, (void *)x);
		printf("pthread_create %i\n", x);
	}


	/* setup hostname variable for use in logs (incase of multiple hosts) */
	if(gethostname(hostname, HOST_NAME_MAX) != 0) {
		sprintf(hostname, "unknown");
	}


	/* now we can set our callback function */
	pcap_loop(handle, -1, packet_queue_handler, NULL);

	/* This only occurs with pcap, not live capture, need signal shiz XXX */

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	return 0;
}
