#CF= -O3 -ftracer -funroll-loops -funsafe-loop-optimizations -ggdb -I/opt/local/include -L/opt/local/lib
CF= -O0 -ggdb -I/opt/local/include -L/opt/local/lib
LIBS = -lcrypto -lssl

all: test_sni_client lookup test_sni_server

sockutils.o: sockutils.h sockutils.c
	cc $(CF) -c sockutils.c

test_sni_client.o: test_sni_client.c sockutils.h
	cc $(CF) -c test_sni_client.c

test_sni_server.o: test_sni_server.c sockutils.h
	cc $(CF) -c test_sni_server.c

lookup.o: lookup.c sockutils.h
	cc $(CF) -c lookup.c

test_sni_client: test_sni_client.o sockutils.o
	cc $(CF) -o test_sni_client test_sni_client.o sockutils.o $(LIBS)

test_sni_server: test_sni_server.o sockutils.o
	cc $(CF) -o test_sni_server test_sni_server.o sockutils.o $(LIBS)

lookup: lookup.o sockutils.o
	cc $(CF) -o lookup lookup.o sockutils.o $(LIBS)

clean:
	rm test_sni_client
	rm test_sni_server
	rm lookup
	rm *.o

