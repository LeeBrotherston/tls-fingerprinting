/* This File Is To Cope With Signal Handling Routines */

void sig_handler (int signo);


/* Function registers all the signals to the sig_handler function */
int register_signals() {
	if (signal(SIGUSR1, sig_handler) == SIG_ERR)
		return 0;
	if (signal(SIGUSR2, sig_handler) == SIG_ERR)
		return 0;
	if (signal(SIGINT, sig_handler) == SIG_ERR)
		return 0;

	return 1;
}


/* Handles a variety of signals being recieved */
void sig_handler (int signo) {
	struct pcap_stat pstats;
	extern FILE *json_fd;
	extern FILE *fpdb_fd;
	extern pcap_t *handle;						/* packet capture handle */
	extern pcap_dumper_t *output_handle;
	extern struct bpf_program fp;					/* compiled filter program (expression) */

	switch (signo) {

		/* Placeholder, will use this for some debugging */
		case SIGUSR1:
			// This is where code goes :)
			break;

		/* Someone has ctrl-c'd the process.... deal */
		case SIGINT:
			// Close File Pointers
			// Not even going to check, because, APP GOING DOWN!!
			fclose(json_fd);
			fclose(fpdb_fd);

			// Sort out libpcap stuff

			// Get some stats on the session
			if(!(pcap_stats(handle, &pstats))) {
				printf("Processed %i%% Of Packets\n",
					(int) (( (float)((float)pstats.ps_recv - (float)pstats.ps_drop) / (float) pstats.ps_recv) * 100) );
				printf("Recieved: %i\n", pstats.ps_recv);
				printf("Dropped: %i\n", pstats.ps_drop);
			}

			// No checking because accoring to the man page, they don't return anything useful o_O
			pcap_freecode(&fp);
			pcap_close(handle);
			if(output_handle != NULL) {
				pcap_dump_close(output_handle);
			}


			exit(1);
			break;
	}


}
