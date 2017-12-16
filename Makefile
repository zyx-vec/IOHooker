#CC=icpc
BINS=gizmo
CC=g++

PLFS_PATH ?= $(HOME)
#PLFS_PATH=/usr/local/lib

# Sierra is odd and doesn't like xstat and fxstat when running in parallel. 
# It also doesn't like unlocked functions or putchar and getchar. These are disabled by default.

# To enable the __xstat and __fxstat functions, -DXSTAT
# To enable _unlocked functions, -DUNLOCKED
# To enable getchar and putchar, -DPUTGETCHAR

OPTS = -g -fPIC -shared -I$(PLFS_PATH)/include -fvisibility=hidden -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -DUNLOCKED -DPUTGETCHAR -DXSTAT
LINKOPTS = -g -fPIC -shared -fvisibility=hidden -Wl,-soname,libmyplfs.so.1 -o libmyplfs.so.1.0.1 -lpthread -ldl -lplfs -L$(PLFS_PATH)/lib -I$(PLFS_PATH)/include
#LINKOPTS = -g -fPIC -shared -fvisibility=hidden -Wl,-soname,libmyplfs.so.1 -o libmyplfs.so.1.0.1 -L/usr/local/lib -L./ -lpthread -lplfs2.5 -ldl

all: libmyplfs

gizmo: gizmo.c
	mpicc -o gizmo gizmo.c

myplfs.o: myplfs.cpp
	$(CC) $(OPTS) -O3 -c myplfs.cpp

libmyplfs.so.1.0.1: myplfs.o
	$(CC) $(LINKOPTS) -O3 myplfs.o

libmyplfs.so.1: libmyplfs.so.1.0.1
	ln -sf libmyplfs.so.1.0.1 libmyplfs.so.1

libmyplfs.so: libmyplfs.so.1
	ln -sf libmyplfs.so.1 libmyplfs.so

libmyplfs: libmyplfs.so

debug:
	rm -Rf *.so* # clean up any symlinks
	$(CC) $(OPTS) -O0 -DDEBUG -c myplfs.cpp
	$(CC) $(LINKOPTS) -O0 myplfs.o
	ln -s libmyplfs.so.1.0.1 libmyplfs.so.1
	ln -s libmyplfs.so.1 libmyplfs.so

	
clean:
	rm -f *.o *.so *.so.* $(BINS)
