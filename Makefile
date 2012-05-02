

CC = gcc #g++ #
CFLAGS = -g  -Wall -Werror #-O2
PROGRAM_NAME = dns_server

HANDIN_FILE = main.c

MAIN_DEPEN = conn dns
MAIN_DEPEN_FILES = main.c
MAIN_COMPL = main.c conn.o cache.o dns.o smartalloc.so

CONN_DEPEN = $(CONN_DEPEN_FILES)
CONN_COMPL = conn.c
CONN_DEPEN_FILES = conn.h conn.c

CACHE_DEPEN = smartalloc $(CACHE_DEPEN_FILES)
CACHE_COMPL = cache.c #smartalloc.so
CACHE_DEPEN_FILES = cache.c cache.h

DNS_DEPEN = smartalloc cache $(DNS_DEPEN_FILES)
DNS_COMPL = dns.c #cache.o #smartalloc.so
DNS_DEPEN_FILES = dns.c dns.h

SMARTALLOC_DEPEN = $(SMARTALLOC_DEPEN_FILES)
SMARTALLOC_COMPL = smartalloc.c
SMARTALLOC_DEPEN_FILES = smartalloc.c smartalloc.h

all: $(PROGRAM_NAME)

$(PROGRAM_NAME): $(MAIN_DEPEN)
	$(CC) $(CFLAGS) -o $@ $(MAIN_COMPL)

conn: $(CONN_DEPEN)
	$(CC) $(CFLAGS) -fPIC -c -o $@.o $(CONN_COMPL) 

dns: $(DNS_DEPEN)
	$(CC) $(CFLAGS) -fPIC -c -o $@.o $(DNS_COMPL) 

cache: $(CACHE_DEPEN)
	$(CC) $(CFLAGS) -fPIC -c -o $@.o $(CACHE_COMPL)

smartalloc:
	$(CC) $(CFLAGS) -shared -c -o $@.so $(SMARTALLOC_COMPL)

handin: $(HANDIN_FILES)
	handin bellardo p2m1 $(HANDIN_FILES)

clean:
	rm -f *~ $(PROGRAM_NAME) *.o *.so 
