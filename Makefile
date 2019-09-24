
OBJS += relocate.o plthijack.o utils.o inject.o

.PHONY: all clean

all: relocate plthijack

$(OBJS): %.o: %.c
	- gcc -c $<

relocate: relocate.o utils.o inject.o
	- gcc -o $@ $^

plthijack: plthijack.o utils.o inject.o
	- gcc -o $@ $^

clean:
	- rm *.o relocate plthijack
