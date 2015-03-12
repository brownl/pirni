#include "pirni.h"

/********************************************
 * SendARPreplyMainRoutine(void* data)
 * 
 * Infinite loop that sends out the spoofed
 * Arp packet
 * *****************************************/
void* SendARPreplyMainRoutine(void* data)
{
	while(1)
	{
		libnet_write(l);
		sleep(10);
	}
	
	return NULL;
}


/***************************************************
 * LaunchThread()
 * 
 * Creates a POSIX thread (SendARPreplyMainRoutine)
 * that sends out the spoofed ARP packet
 * ************************************************/
void LaunchThread()
{
	// Create the thread using POSIX routines.

	pthread_attr_t	attr;
	pthread_t		posixThreadID;
	int				returnVal;
	
	returnVal	=	pthread_attr_init(&attr);

	assert(!returnVal);

	returnVal = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	assert(!returnVal);

	int threadError = pthread_create(&posixThreadID, &attr, &SendARPreplyMainRoutine, NULL);

	returnVal = pthread_attr_destroy(&attr);

	assert(!returnVal);
	if (threadError != 0)
	{
		printf("[-] Error working with POSIX threads\n");
	}
	return;
}
