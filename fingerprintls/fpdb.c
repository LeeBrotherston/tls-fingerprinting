/* Functions, etc used in the management of the internal fingerprint database held in memory */


/* create_fpdb will allocate memory and create a skeleton structure of fingerprint structs to load data into */
/* In reality the structs are actually pointers to the binary file loaded in memory, but this still needs to */
/* be managed */
struct fingerprint_new* create_fpdb(int count) {
	struct fingerprint_new *fp_first, *fp_current, *fp_temp;
	int i;
	/* This malloc suitable for userland only, will need to use another variation if */
	/* any of this code makes it into a kernel */
	fp_temp = fp_current = fp_first = malloc(((int)count * sizeof(struct fingerprint_new)));

	/* Catch errors */
	if (fp_first == NULL) {
		return NULL;
	}

	/* Initialise a chain of fingerprints */
	/* Currently not sorted, tree'd, index, etc */
	for(i = 1; i <= count; i++) {
		fp_current->next = ++fp_temp;
		fp_current = fp_temp;
	}
	/* Set an easy to find end */
	fp_current->next = NULL;

	/* Return pointer to the first state in the chain */
	return fp_first;

}
