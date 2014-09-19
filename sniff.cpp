#include <iostream>
#include <iomanip>
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <netdb.h>
#include <signal.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include "sniff_pack.h"

int sigcatch = 0;
void sigcatcher(int s)
{
	std::cout << std::endl << "SIGNAL " << s << std::endl;
	sigcatch = 1;
}

int main(int argc, char** argv)
{

	struct sigaction siginthandler;
	siginthandler.sa_handler = sigcatcher;
	sigemptyset(&siginthandler.sa_mask);
	siginthandler.sa_flags = 0;
	sigaction(SIGINT, &siginthandler, NULL);
	sigaction(SIGHUP, &siginthandler, NULL);
	sigaction(SIGQUIT, &siginthandler, NULL);
	sigaction(SIGTERM, &siginthandler, NULL);
	sigaction(SIGKILL, &siginthandler, NULL);

	int socketfd = socket(AF_PACKET, SOCK_RAW, ntohs(0x0003));
	if (socketfd < 0)
	{
		std::cout << "sockerror: " << strerror(errno) << std::endl;
		return -1;
	}

	int packbufsize = 1024*64;
	unsigned char packbuf[packbufsize];
	struct sockaddr src_addr;
	socklen_t addrlen;
	memset(packbuf, 0, packbufsize);
	memset(&src_addr, 0, sizeof(sockaddr));
	memset(&addrlen, 0, sizeof(addrlen));
	int flags = 0;
	
	ssize_t packsize = 0;
	while (!sigcatch) {
		packsize = recvfrom(socketfd, packbuf, packbufsize, flags, &src_addr, &addrlen);
		if (packsize < 0) continue;
		eth_unpack(packbuf, packsize);
	}
	close(socketfd);
	return 0;
}
