
#include "os.h"
#include "http5.h"

static int
handleall(Http5message *output, Http5message *input)
{
	Http5buf *outbuf;
	outbuf = &output->buf;
	if(input->state == HTTP5_DONE && output->state == HTTP5_READY){
		if(http5ok(output) == -1)
			return -1;
		if(http5putheader(output, "content-type", "text/plain") == -1)
			return -1;
		char *body = "hello world\n";
		if(http5putbody(output, body, strlen(body)) == -1)
			return -1;
		output->state = HTTP5_WRITE;
	}
	if(input->state == HTTP5_DONE && output->state == HTTP5_DONE){
		http5clear(input);
		http5clear(output);
	}
	return 0;
}

static int
handleget(Http5message *output, Http5message *input)
{
	fprintf(stderr, "handleget: instate: %d outstate: %d\n", input->state, output->state);
	if(output->state == HTTP5_READY){
		Http5buf *outbuf = &output->buf;
		http5request(output, "GET", "/", "HTTP/1.1");
		if(http5putheader(output, "Host", "www.google.com") == -1)
			return -1;
		if(http5putbody(output, "", 0) == -1)
			return -1;

		fprintf(stderr, "request:%.*s--\n", (int)outbuf->len, outbuf->buf);
		output->state = HTTP5_WRITE;
		input->state = HTTP5_READY;
	}
	if(output->state == HTTP5_DONE && input->state == HTTP5_DONE){
		Http5buf *inbuf = &input->buf;
		fprintf(stderr, "handleget: chunk size %zd\n", input->body.len);
		input->state = HTTP5_PARSE_CHUNK;
		if(input->body.len == 0)
			input->state = HTTP5_CLOSE;
	}
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
	http5connect("2607:f8b0:4005:806::200e", 80, 1<<20, 1<<20, handleget);
	return http5server(port, 8192, 8192, handleall);
}
