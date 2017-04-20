
#ifdef WIN32
#include <stdio.h>
#include <winsock2.h>
#else
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <string.h>
#include <ctype.h>
#define closesocket close
#define ioctlsocket ioctl
#endif

#define nelem(x) (sizeof(x)/sizeof(x[0]))
