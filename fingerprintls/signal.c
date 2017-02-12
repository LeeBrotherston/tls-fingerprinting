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
along with FingerprinTLS.  If not, see <http://www.gnu.org/licenses/>.

Exciting Licence Info Addendum.....

FingerprinTLS is additionally released under the "don't judge me" program
whereby it is forbidden to rip into me too harshly for programming
mistakes, kthnxbai.

*/

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


/* Handles a variety of signals being received */
void sig_handler (int signo) {
	struct pcap_stat pstats;
	extern FILE *json_fd;
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
			// Get some stats on the session
			if(!(pcap_stats(handle, &pstats))) {
				printf("Processed %i%% Of Packets\n",
					(int) (( (float)((float)pstats.ps_recv - (float)pstats.ps_drop) / (float) pstats.ps_recv) * 100) );
				printf("Received: %i\n", pstats.ps_recv);
				printf("Dropped: %i\n", pstats.ps_drop);
			}

			/* Stop the pcap loop */
			pcap_breakloop(handle);

			// Close File Pointers
			fclose(json_fd);

			// No checking because accoring to the man page, they don't return anything useful o_O
			pcap_freecode(&fp);
			pcap_close(handle);
			if(output_handle != NULL) {
				pcap_dump_close(output_handle);
			}


			exit(1);
			break;

		default:
			printf("Caught signal: %i\n", signo);
			exit(0);
	}


}
