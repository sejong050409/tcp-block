all: tcp-block

tcp-block: tcp-block.o
	gcc -o tcp-block tcp-block.o -lpcap

tcp-block.o: tcp-block.c headers.h
	gcc -c -o tcp-block.o tcp-block.c

clean:
	rm -f tcp-block
	rm -f *.o
