CFLAGS = -Wall -Wpedantic -g -O3

cypher: crack.o sha256.o
	gcc $(CFLAGS) crack.o sha256.o -o crack

sha256.o: sha256.c sha256.h
	gcc $(CFLAGS) -c sha256.c

crack.o: crack.c sha256.h
	gcc $(CFLAGS) -c crack.c

clean:
	rm *.o crack
