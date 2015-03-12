# If you are compiling ON the iPhone using gcc, then uncomment this line and comment out the line containing arm-apple-darwin9-gcc

#CC=gcc

# The line below needs to be commented out if you want to compile natively ON the iphone
CC=arm-apple-darwin9-gcc
CFLAGS=-Wall -pthread -lpcap

main: pirni.c
	$(CC) $(CFLAGS) pirni.c threads.c sniffer.c -o pirni -lnet
#	ldid -S pirni
clean:
	rm -f pirni pirno.o threads.o sniffer.o
