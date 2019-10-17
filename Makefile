CC = g++
CFLAGS = -I lib -O3 -fopenmp -g -I/usr/include/openssl-1.0

hidedata: src/hidedata.o lib/rb_tree/rb_tree.o src/hash_engine.o src/hash_method.o src/util.o
	$(CC) $^ -o $@ $(CFLAGS) -Wl,-Bstatic -L./lib/cjson/ -lcjson -Wl,-Bdynamic -L/usr/lib/openssl-1.0 -lgmp -lcrypto -lbsd

oclhidedata: src/oclhidedata.o src/hash_method.o lib/vanitygen/pattern.o lib/vanitygen/util.o lib/rb_tree/rb_tree.o src/hash_engine.o src/util.o src/hash_engine_ocl.o
	$(CC) $^ -o $@ $(CFLAGS) -Wl,-Bstatic -L./lib/cjson/ -lcjson -Wl,-Bdynamic -L/usr/lib/openssl-1.0 -lgmp -lcrypto -lbsd -lOpenCL -lpcre

parsedata: src/parsedata.o lib/rb_tree/rb_tree.o src/util.o
	$(CC) $^ -o $@ $(CFLAGS) -Wl,-Bstatic -L./lib/libbtc/.libs -lbtc -L./lib/libbtc/src/secp256k1/.libs -lsecp256k1 -L./lib/cjson/ -lcjson -Wl,-Bdynamic -lgmp -lcrypto -lcurl

clean:
	rm -v src/*.o hidedata oclhidedata
