
typedef struct Http5 Http5;
typedef struct Http5ref Http5ref;
typedef struct Http5buf Http5buf;
typedef struct Http5header Http5header;
typedef struct Http5request Http5request;
typedef struct Http5response Http5response;

enum {
	HTTP5_READ_READY = 1<<0,
	HTTP5_WRITE_READY = 1<<1,

	HTTP5_READ_ERROR = 1<<2,
	HTTP5_READ_EOF = 1<<3,
	HTTP5_WRITE_ERROR = 1<<4,
	HTTP5_PROTOCOL_ERROR = 1<<5,
	HTTP5_PROCESS_ERROR = 1<<6,
	HTTP5_ERROR_MASK = HTTP5_READ_ERROR | HTTP5_READ_EOF | HTTP5_WRITE_ERROR | HTTP5_PROTOCOL_ERROR | HTTP5_PROCESS_ERROR,

	HTTP5_PARSE_REQUEST = 0,
	HTTP5_PARSE_HEADER = 1,
	HTTP5_PARSE_BODY = 2,
	HTTP5_FLUSH_OUTPUT = 3,
};

struct Http5ref {
	size_t off;
	size_t len;
};

struct Http5header {
	Http5ref key;
	Http5ref val;
};

struct Http5request {
	Http5ref method, resource, version;
	Http5ref body;
	Http5header headers[32];
	size_t nheaders;
	int state;
};

struct Http5response {
	Http5ref version, code, reason;
	Http5ref body;
	Http5header headers[32];
	size_t nheaders;
};

struct Http5buf {
	char *buf;
	size_t off;
	size_t len;
	size_t cap;
};

struct Http5 {
	Http5request req;
	Http5response resp;
	Http5buf input;
	Http5buf output;
};


int http5server(int port, int incap, int outcap);
