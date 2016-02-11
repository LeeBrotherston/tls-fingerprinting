# Commented this out for now, not sure how many use klang
#CC=g++
CFLAGS=-Wall -pedantic -Os
LDFLAGS=-lpcap

all: fingerprintls

fingerprintls:
	$(CC) $(CFLAGS) fingerprintls.c -o fingerprintls $(LDFLAGS)

clean:
	rm -rf fingerprintls fingerprintls.o

.PHONY: clean
