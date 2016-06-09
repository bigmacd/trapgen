.SUFFIXES:
.SUFFIXES : .cpp .o

CC=gcc 
CFLAGS = -D_IRIX -D_USE_PACKETLIB -D_LANGUAGE_C_PLUS_PLUS -O2
INCLUDES = -I. -I../pktlib -I../common

LIBS = -lstdc++ -L../pktlib -lPktLib

CFILES= ../common/IrixSysUptime.cpp

OBJECTS = ${CFILES:.cpp=.o}

.SUFFIXES : .cpp .o
.cpp.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $*.o

all:	$(OBJECTS)
	$(CC) $(CFLAGS) $(INCLUDES) TrapGen.cpp -o trapgen $(OBJECTS) $(LIBS)

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



