#CF= -O3 -ftracer -funroll-loops -funsafe-loop-optimizations -ggdb -I/opt/local/include -L/opt/local/lib
CF= -O0 -ggdb -I/opt/local/include -L/opt/local/lib -I/opt/openssl/include
LIBS = -lcrypto -lssl

all: test_sni_client lookup test_sni_server txt2nid parse_x509 nid2sn

parse_x509.o: sockutils.h parse_x509.c
	cc $(CF) -c parse_x509.c

nid2sn.o: nid2sn.c sockutils.h
	cc $(CF) -c nid2sn.c

sockutils.o: sockutils.h sockutils.c
	cc $(CF) -c sockutils.c

test_sni_client.o: test_sni_client.c sockutils.h
	cc $(CF) -c test_sni_client.c

test_sni_server.o: test_sni_server.c sockutils.h
	cc $(CF) -c test_sni_server.c

txt2nid.o: txt2nid.c sockutils.h
	cc $(CF) -c txt2nid.c

lookup.o: lookup.c sockutils.h
	cc $(CF) -c lookup.c

test_sni_client: test_sni_client.o sockutils.o
	cc $(CF) -o test_sni_client test_sni_client.o sockutils.o $(LIBS)

nid2sn: nid2sn.o sockutils.o
	cc $(CF) -o nid2sn nid2sn.o sockutils.o $(LIBS)

test_sni_server: test_sni_server.o sockutils.o
	cc $(CF) -o test_sni_server test_sni_server.o sockutils.o $(LIBS)

lookup: lookup.o sockutils.o
	cc $(CF) -o lookup lookup.o sockutils.o $(LIBS)

txt2nid: txt2nid.o sockutils.o
	cc $(CF) -o txt2nid txt2nid.o sockutils.o $(LIBS)

parse_x509: parse_x509.o sockutils.o
	cc $(CF) -o parse_x509 parse_x509.o sockutils.o $(LIBS)

clean:
	rm parse_x509
	rm test_sni_client
	rm test_sni_server
	rm lookup
	rm txt2nid
	rm *.o

