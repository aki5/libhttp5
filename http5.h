
typedef struct Http5ref Http5ref;
typedef struct Http5buf Http5buf;
typedef struct Http5header Http5header;
typedef struct Http5message Http5message;
typedef struct Http5message Http5message;

enum {
	HTTP5_TYPE_REQUEST = 1,
	HTTP5_TYPE_RESPONSE = 2,

	HTTP5_PARSE_LINE = 0,
	HTTP5_PARSE_HEADER = 1,
	HTTP5_PARSE_BODY = 2,
	HTTP5_FLUSH_OUTPUT = 3,

	HTTP5_READ_READY = 1<<0,
	HTTP5_WRITE_READY = 1<<1,

	HTTP5_READ_ERROR = 1<<2,
	HTTP5_READ_EOF = 1<<3,
	HTTP5_WRITE_ERROR = 1<<4,
	HTTP5_PROTOCOL_ERROR = 1<<5,
	HTTP5_PROCESS_ERROR = 1<<6,
	HTTP5_ERROR_MASK = HTTP5_READ_ERROR | HTTP5_READ_EOF | HTTP5_WRITE_ERROR | HTTP5_PROTOCOL_ERROR | HTTP5_PROCESS_ERROR,
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
	union {
		Http5ref method;
		Http5ref reason;
	};
	union {
		Http5ref resource;
		Http5ref code;
	};
	Http5ref version;
	Http5ref body;
	Http5header headers[32];
	size_t nheaders;
	Http5buf buf;
};

int http5connect(char *addr, int port, int incap, int outcap, int (*handler)(Http5message *, Http5message *));
int http5server(int port, int incap, int outcap, int (*handler)(Http5message *, Http5message *));

int http5request(Http5message *req, char *method, char *resource, char *version);

int http5ok(Http5message *resp);
int http5code(Http5message *resp, int code);
int http5respond(Http5message *resp, char *version, char *code, char *reason);

int http5putheader(Http5message *msg, char *key, char *value);
int http5putbody(Http5message *msg, char *body, size_t len);
