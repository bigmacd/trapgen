.SUFFIXES:
.SUFFIXES : .cpp .o

CC=gcc 
CFLAGS = -D_SOLARIS -O2
INCLUDES = -I. -I../pktlib -I../common

LIBS = -L../pktlib -lPktLib -L/usr/local/lib/gcc-lib/sparc-sun-solaris2.6/2.95.3 -lstdc++ -lsocket -lnsl -lkstat


CFILES= ../common/SolarisSysUptime.cpp

OBJECTS = ${CFILES:.cpp=.o}

all:	$(OBJECTS)
	$(CC) $(CFLAGS) $(INCLUDES) TrapGen.cpp -o trapgen  $(OBJECTS) $(LIBS)

clean:
	rm -f *~ $(OBJECTS) *.o trapgen

% : %.cpp
	$(CC) $(CFLAGS) $(INCLUDES) $< -o $*

%.o : %.cpp
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $*.o

.c.i :
	$(CC) $(CFLAGS) $(INCLUDES) -E -C $< > $*.i

.c.s :
	$(CC) $(CFLAGS) $(INCLUDES) -S $< > $*.s

%.mk:	%.c
	$(CC) $(INCLUDES) -M $< >$@
	${edit_depend}



