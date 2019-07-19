CC = g++
CFLAGS = -I lib -O3 -fopenmp -g -rdynamic
LIBS = -lgmp -lssl -lcrypto -lbsd

OBJS = src/hidedata.o lib/rb_tree/rb_tree.o src/hash_engine.o src/hash_method.o

hidedata: $(OBJS)
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS)

clean:
	rm -v $(OBJS) hidedata
