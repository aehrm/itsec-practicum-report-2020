CC = g++
CFLAGS = -I lib -O3 -fopenmp -g -I/usr/include/openssl-1.0
LIBS = -Wl,-Bstatic -L./lib/libbtc/.libs -L./lib/libbtc/src/secp256k1/.libs -lbtc -lsecp256k1 -Wl,-Bdynamic -L/usr/lib/openssl-1.0 -lgmp -lcrypto -lbsd
LIBS_OPENCL = -lOpenCL -lpcre

OBJS = src/hidedata.o lib/rb_tree/rb_tree.o src/hash_engine.o src/hash_method.o src/util.o
OBJS_OCL = src/oclhidedata.o src/hash_method.o lib/vanitygen/pattern.o lib/vanitygen/util.o lib/rb_tree/rb_tree.o src/hash_engine.o src/util.o src/hash_engine_ocl.o

hidedata: $(OBJS)
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS)

oclhidedata: $(OBJS_OCL)
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS) $(LIBS_OPENCL)

clean:
	rm -v $(OBJS) $(OBJS_OCL) hidedata oclhidedata
