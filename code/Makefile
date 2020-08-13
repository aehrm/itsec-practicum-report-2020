CC = g++
CFLAGS = -I lib -O3 -fopenmp -g

.PHONY: default
default: hidedata buildtx parsedata

lib/cjson/libcjson.so:
	(cd lib/cjson && make)

lib/libbtc/.libs/libbtc.so:
	(cd lib/libbtc && ./autogen.sh && ./configure --disable-wallet --disable-tools --disable-net --disable-tests && make)

hidedata: src/hidedata.o lib/rb_tree/rb_tree.o src/hash_engine.o src/hash_method.o src/util.o | lib/cjson/libcjson.so
	$(CC) $^ -o $@ $(CFLAGS) -Wl,-Bstatic -L./lib/cjson/ -lcjson -Wl,-Bdynamic -lgmp -lcrypto -lbsd

buildtx: src/buildtx.o src/util.o src/rpc.o | lib/cjson/libcjson.so lib/libbtc/.libs/libbtc.so
	$(CC) $^ -o $@ $(CFLAGS) -Wl,-Bstatic -L./lib/libbtc/.libs -lbtc -L./lib/libbtc/src/secp256k1/.libs -lsecp256k1 -L./lib/cjson/ -lcjson -Wl,-Bdynamic -lgmp -lcrypto -lcurl

parsedata: src/parsedata.o lib/rb_tree/rb_tree.o src/util.o src/rpc.o | lib/cjson/libcjson.so lib/libbtc/.libs/libbtc.so
	$(CC) $^ -o $@ $(CFLAGS) -Wl,-Bstatic -L./lib/libbtc/.libs -lbtc -L./lib/libbtc/src/secp256k1/.libs -lsecp256k1 -L./lib/cjson/ -lcjson -Wl,-Bdynamic -lgmp -lcrypto -lcurl

clean:
	-rm -v src/*.o hidedata buildtx parsedata
	-(cd lib/cjson && make clean)
	-(cd lib/libbtc && make clean)
