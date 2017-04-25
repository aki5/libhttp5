
typedef struct Http5ref Http5ref;
typedef struct Http5buf Http5buf;
typedef struct Http5header Http5header;
typedef struct Http5message Http5message;
typedef struct Http5chan Http5chan;

enum {
	HTTP5_TYPE_REQUEST = 1,
	HTTP5_TYPE_RESPONSE = 2,

	HTTP5_READY = 0,
	HTTP5_PARSE_LINE = 0,
	HTTP5_PARSE_HEADER,
	HTTP5_PARSE_BODY,
	HTTP5_PARSE_CHUNK,
	HTTP5_PARSE_CHUNK_BODY,
	HTTP5_PARSE_TRAILER,
	HTTP5_WRITE,
	HTTP5_DONE,
	HTTP5_CLOSE,

	HTTP5_READ_READY = 1<<0,
	HTTP5_WRITE_READY = 1<<1,

	HTTP5_NORMAL_CLOSE = 1<<2,
	HTTP5_READ_ERROR = 1<<3,
	HTTP5_WRITE_ERROR = 1<<4,
	HTTP5_PROTOCOL_ERROR = 1<<5,
	HTTP5_PROCESS_ERROR = 1<<6,
	HTTP5_ERROR_MASK = HTTP5_READ_ERROR | HTTP5_NORMAL_CLOSE | HTTP5_WRITE_ERROR | HTTP5_PROTOCOL_ERROR | HTTP5_PROCESS_ERROR,
};

struct Http5ref {
	size_t off;
	size_t len;
};

struct Http5header {
	Http5ref key;
	Http5ref val;
};

struct Http5buf {
	char *buf;
	size_t off;
	size_t len;
	size_t cap;
};

struct Http5message {
	int type;
	int state;
	Http5ref line[3];
	Http5ref body;
	Http5header headers[32];
	size_t nheaders;
	Http5buf buf;
};


struct Http5chan {
	char name[128];
	Http5message input;
	Http5message output;
	void *state;
	int (*handler)(void **statep, Http5message *, Http5message *);
};


int http5connect(char *addr, int port, int incap, int outcap, int (*handler)(void **statep, Http5message *, Http5message *));
int http5server(int port, int incap, int outcap, int (*handler)(void **statep, Http5message *, Http5message *));

int http5request(Http5message *req, char *method, char *resource, char *version);

int http5ok(Http5message *resp);
int http5code(Http5message *resp, int code);
int http5putline(Http5message *resp, char *first, char *second, char *third);

void http5clear(Http5message *msg);
int http5putheader(Http5message *msg, char *key, char *value);
int http5putbody(Http5message *msg, char *body, size_t len);

void http5read(Http5message *msg);
void http5write(Http5message *msg);
void http5close(Http5message *msg);