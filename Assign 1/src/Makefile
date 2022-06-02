$(CC)=gcc
validate: demoprogram.o simple_crypto.o
	$(CC) demoprogram.o simple_crypto.o -o encrypt

demoprogram.o : demoprogram.c simple_crypto.h
	$(CC) -c demoprogram.c
simple_crypto.o: simple_crypto.c simple_crypto.h
	$(CC) -c simple_crypto.c

Clean: 
	rm *.o encrypt