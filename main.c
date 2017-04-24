
#include "os.h"
#include "http5.h"

static int
handleall(void **statep, Http5message *output, Http5message *input)
{
	int state;

	state = *(int*)statep;
	switch(state){
	case 0:
		if(input->state == HTTP5_DONE){
			if(http5ok(output) == -1)
				return -1;
			if(http5putheader(output, "content-type", "text/plain") == -1)
				return -1;
			char *body = "hello world\n";
			if(http5putbody(output, body, strlen(body)) == -1)
				return -1;
			http5clear(input);
			http5write(output);
			*statep = (void *)1;
		}
		break;
	case 1:
		if(output->state == HTTP5_DONE){
			http5clear(output);
			*statep = (void *)0;
		}
		break;
	}
	return 0;
}

static int
handleget(void **statep, Http5message *output, Http5message *input)
{
	int state;
	state = *(int*)statep;
	switch(state){
	case 0:
		fprintf(stderr, "handleget: instate: %d outstate: %d\n", input->state, output->state);
		if(output->state == HTTP5_READY){
			Http5buf *outbuf = &output->buf;
			http5putline(output, "GET", "/", "HTTP/1.1");
			if(http5putheader(output, "Host", "www.google.com") == -1)
				return -1;
			if(http5putbody(output, "", 0) == -1)
				return -1;
			http5write(output);
			http5read(input);
			fprintf(stderr, "request:%.*s--\n", (int)outbuf->len, outbuf->buf);
			*statep = (void *)1;
		}
		break;
	case 1:
		if(output->state == HTTP5_DONE && input->state == HTTP5_DONE){
			Http5buf *inbuf = &input->buf;
			fprintf(stderr, "handleget: chunk size %zd\n", input->body.len);
			input->state = HTTP5_PARSE_CHUNK;
			if(input->body.len == 0){
				http5close(output);
			}
		}
		break;
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
	http5connect("2607:f8b0:4005:806::200e", 80, 1<<16, 1<<16, handleget);
	return http5server(port, 8192, 8192, handleall);
}
