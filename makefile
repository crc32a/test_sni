#CF= -O3 -ftracer -funroll-loops -funsafe-loop-optimizations -ggdb -I/opt/local/include -L/opt/local/lib
CF= -O0 -ggdb -I/opt/local/include -L/opt/local/lib
LIBS = -lcrypto -lssl
all: test_sni_client lookup

sockutils.o: sockutils.h sockutils.c
	cc $(CF) -c sockutils.c

test_sni_client.o: test_sni_client.c sockutils.h
	cc $(CF) -c test_sni_client.c

lookup.o: lookup.c sockutils.h
	cc $(CF) -c lookup.c

test_sni_client: test_sni_client.o sockutils.o
	cc $(CF) -o test_sni_client test_sni_client.o sockutils.o $(LIBS)

lookup: lookup.o sockutils.o
	cc $(CF) -o lookup lookup.o sockutils.o

clean:
	rm test_sni_client
	rm lookup
	rm *.o

