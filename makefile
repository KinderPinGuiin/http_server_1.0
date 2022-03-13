LIBS = ./libs
addr_internet_dir = $(LIBS)/adresse_internet/
http_dir = $(LIBS)/http/
hashtable_dir = $(LIBS)/hashtable/
c_utils_dir = $(LIBS)/c_utils/
socket_tcp_dir = $(LIBS)/socket_tcp/
list_dir = $(LIBS)/list/
yml_parser_dir = $(LIBS)/yml_parser/

CC = gcc
CFLAGS = -std=c18 \
  -Wall -Wconversion -Werror -Wextra -Wfatal-errors -Wpedantic -Wwrite-strings \
  -O2 -pthread -c -I$(addr_internet_dir) -I$(http_dir) -I$(hashtable_dir)      \
  -I$(c_utils_dir) -I$(socket_tcp_dir) -I$(list_dir) -I$(yml_parser_dir)
LDFLAGS = -pthread -lrt
VPATH = $(addr_internet_dir):$(http_dir):$(hashtable_dir):$(c_utils_dir):$(socket_tcp_dir):$(list_dir):$(yml_parser_dir)
objects_server = $(hashtable_dir)hashtable.o \
  $(addr_internet_dir)adresse_internet.o $(http_dir)http.o \
  $(socket_tcp_dir)socket_tcp.o $(list_dir)list.o server.o \
  $(yml_parser_dir)yml_parser.o
executable_server = server

all: $(executable_server)

clean:
	$(RM) $(executable_server) $(objects_server)

$(executable_server): $(objects_server)
	$(CC) $(objects_server) $(LDFLAGS) -o $(executable_server)

server.o: server.c
$(http_dir)http.o: http.c http.h
$(addr_internet_dir)adresse_internet.o: adresse_internet.c adresse_internet.h
$(hashtable_dir)hashtable.o: hashtable.c hashtable.h
$(socket_tcp_dir)socket_tcp.o: socket_tcp.c socket_tcp.h
$(list_dir)list.o: list.c list.h
$(yml_parser_dir)yml_parser.o: yml_parser.c yml_parser.h
