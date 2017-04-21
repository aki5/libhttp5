
#include "os.h"
#include "http5.h"

static int
handleall(Http5message *resp, Http5message *req)
{
	Http5buf *outbuf;
	outbuf = &resp->buf;
//fprintf(stderr, "process:%.*s--\n", (int)inbuf->len, inbuf->buf);
	if(http5ok(resp) == -1)
		return -1;
	if(http5putheader(resp, "content-type", "text/plain") == -1)
		return -1;
	char *body = "hello world\n";
	if(http5putbody(resp, body, strlen(body)) == -1)
		return -1;
	req->state = HTTP5_FLUSH_OUTPUT;
	return 0;
}

int
main(int argc, char *argv[])
{
	int port = 5555;
#ifdef _WIN32
	WSADATA wsadata;
	if(WSAStartup(MAKEWORD(2,2), &wsadata) != 0){
		fprintf(stderr, "winsock initialization failed\n");
		exit(1);
	}
#endif
	if(argc > 1)
		port = strtol(argv[1], NULL, 10);
	return http5server(port, 8192, 8192, handleall);
}
