CC=clang
CFLAGS=-pedantic -Wall -g --std=c11
BIN=extractamundo

all: ${BIN}

extractamundo.o: extractamundo.c *.h

install: ${BIN}
	install -o root -g root -m 0755 -s -Z ${BIN} /usr/bin/${BIN}

clean: 
	rm -f *.o ${BIN}
