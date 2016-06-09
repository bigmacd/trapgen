.SUFFIXES:
.SUFFIXES : .cpp .o

CC=gcc 
#CC=g++
#CFLAGS = -D_HPUX -D_USE_PACKETLIB -O2
CFLAGS = -g -D_HPUX -D_USE_PACKETLIB 
INCLUDES = -I. -I../pktlib -I../common


LIBS = -L../pktlib -lPktLib -lstdc++ 

CFILES= ../common/HpuxSysUpTime.cpp 

OBJECTS = ${CFILES:.cpp=.o}

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



