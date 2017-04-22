
#if defined(_WIN32)
#include <stdio.h>
#include <winsock2.h>
#include <Ws2ipdef.h>
typedef int ssize_t;
typedef int socklen_t;
#define sockerrno WSAGetLastError()
#define wouldblock(err) ((err) == WSAEINPROGRESS || (err) == WSAEWOULDBLOCK)
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
#define sockerrno errno
#define wouldblock(err) ((err) == EINPROGRESS || (err) == EWOULDBLOCK || (err) == EAGAIN)
#endif

#define nelem(x) (sizeof(x)/sizeof(x[0]))
