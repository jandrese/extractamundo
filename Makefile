CC=clang
CFLAGS=-pedantic -Wall -g --std=c11
RM=rm -f

all: extractamundo 

clean: 
	${RM} *.o
