CC = g++
CFLAGS = -I lib -O3 -fopenmp -g -rdynamic -I/usr/include/openssl-1.0
LIBS = -lgmp -lcrypto -lbsd -L/usr/lib/openssl-1.0
LIBS_OPENCL = -lOpenCL -lpcre

OBJS = src/hidedata.o lib/rb_tree/rb_tree.o src/hash_engine.o src/hash_method.o
OBJS_OCL = src/oclhidedata.o lib/vanitygen/pattern.o lib/vanitygen/util.o lib/rb_tree/rb_tree.o src/hash_engine.o src/hash_engine_ocl.o

hidedata: $(OBJS)
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS)

oclhidedata: $(OBJS_OCL)
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS) $(LIBS_OPENCL)

clean:
	rm -v $(OBJS) $(OBJS_OCL) hidedata oclhidedata
