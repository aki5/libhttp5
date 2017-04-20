
#include "os.h"
#include "http5.h"

int
main(int argc, char *argv[])
{
	int port = 5555;
#ifdef WIN32
	WSADATA wsadata;
	if(WSAStartup(MAKEWORD(2,2), &wsadata) != 0){
		fprintf(stderr, "winsock initialization failed\n");
		exit(1);
	}
#endif
	if(argc > 1)
		port = strtol(argv[1], NULL, 10);
	return http5server(port, 8192, 8192);
}
