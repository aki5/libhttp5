
#include "os.h"
#include "http5.h"

typedef struct Http5chan Http5chan;

struct Http5chan {
	char name[128];
	Http5message input;
	Http5message output;
	void *state;
	int (*handler)(void **statep, Http5message *, Http5message *);
};

static int
iswhite(int c)
{
	switch(c){
	case '\t': case '\v': case '\f': case ' ':
		return 1;
	}
	return 0;
}

static int
isnonspace(int c)
{
	switch(c){
	case '\t': case '\v': case '\f': case ' ': case '\r': case '\n':
		return 0;
	}
	return 1;
}

static int
islenchar(int c)
{
	switch(c){
	case '\t': case '\v': case '\f': case ' ': case '\r': case '\n': case ';':
		return 0;
	}
	return 1;
}

static int
iskeychar(int c)
{
	switch(c){
	case '\r': case '\n': case ':':
		return 0;
	}
	return 1;
}

static int
isvaluechar(int c)
{
	switch(c){
	case '\r': case '\n':
		return 0;
	}
	return 1;
}

static int
skipspace(char *buf, size_t *offp, size_t len)
{
	size_t off = *offp;
	while(off < len && iswhite(buf[off]))
		off++;
	if(off == len)
		return -1;
	if(*offp == off)
		return -2;
	*offp = off;
	return 0;
}

static int
skipnonspace(char *buf, size_t *offp, size_t len)
{
	size_t off = *offp;
	while(off < len && isnonspace(buf[off]))
		off++;
	if(off == len)
		return -1;
	*offp = off;
	return 0;
}

static int
skipkey(char *buf, size_t *offp, size_t len)
{
	size_t off = *offp;
	while(off < len && iskeychar(buf[off]))
		off++;
	if(off == len)
		return -1;
	*offp = off;
	return 0;
}

static int
skipvalue(char *buf, size_t *offp, size_t len)
{
	size_t off = *offp;
	while(off < len && isvaluechar(buf[off]))
		off++;
	if(off == len)
		return -1;
	*offp = off;
	return 0;
}

static int
skipchar(char *buf, size_t *offp, size_t len, int ch)
{
	size_t off = *offp;
	if(off == len)
		return -1;
	if(buf[off++] != ch)
		return -2;
	*offp = off;
	return 0;
}

static int
skiplength(char *buf, size_t *offp, size_t len)
{
	size_t off = *offp;
	while(off < len && islenchar(buf[off]))
		off++;
	if(off == len)
		return -1;
	if(off == *offp)
		return -2;
	*offp = off;
	return 0;
}

static int
skipendline(char *buf, size_t *offp, size_t len)
{
	size_t off = *offp;
	if(off == len)
		return -1;
	if(buf[off++] != '\r')
		return -2;
	if(off == len)
		return -1;
	if(buf[off++] != '\n')
		return -2;
	*offp = off;
	return 0;
}

static void
http5tolower(Http5buf *htbuf, Http5ref *ref)
{
	char *buf;
	size_t i, end;
	buf = htbuf->buf;
	i = ref->off;
	end = i + ref->len;
	for(; i < end; i++){
		int ch = buf[i];
		// this is ascii-specific, which is
		// approppriate since http is ascii.
		if(ch >= 0x41 && ch <= 0x5a)
			ch += 32;
		buf[i] = ch;
	}
}

static int
http5cmplow(Http5ref *ref, Http5buf *htbuf, char *key)
{
	char *p;
	size_t i, keylen;
	if(ref == NULL)
		return -1;
	keylen = strlen(key);
	keylen = keylen < ref->len ? keylen : ref->len;
	p = htbuf->buf + ref->off;
	for(i = 0; i < keylen; i++){
		int ch = p[i];
		if(ch >= 0x41 && ch <= 0x5a)
			ch += 32;
		if(ch < key[i])
			return -1;
		else if(ch > key[i])
			return 1;
	}
	return 0;
}

static int
http5cmp(Http5ref *ref, Http5buf *htbuf, char *key)
{
	size_t keylen;
	if(ref == NULL)
		return -1;
	keylen = strlen(key);
	keylen = keylen < ref->len ? keylen : ref->len;
	return memcmp(htbuf->buf + ref->off, key, keylen);
}

static Http5ref *
http5header(Http5message *req, char *key)
{
	Http5buf *htbuf;
	char *buf;
	size_t i, keylen;

	keylen = strlen(key);
	htbuf = &req->buf;
	buf = htbuf->buf;
	for(i = 0; i < req->nheaders; i++){
		Http5header *hdr = req->headers + i;
		if(keylen == hdr->key.len && !memcmp(buf+hdr->key.off, key, keylen))
			return &hdr->val;
	} 
	return NULL;
}

static int
http5number(Http5buf *htbuf, Http5ref *ref, size_t *valp)
{
	char *buf;
	size_t i, end;
	size_t tval, val;
	int digit;

	buf = htbuf->buf;
	i = ref->off;
	end = i + ref->len;
	val = 0;
	for(; i < end; i++){
		digit = buf[i];
		if(digit < '0' || digit > '9')
			return -1;
		tval = val * 10 + (digit - '0');
		if(tval < val)
			return -1;
		val = tval;
	}
	*valp = val;
	return 0;
}
static int
http5hex(Http5buf *htbuf, Http5ref *ref, size_t *valp)
{
	char *buf;
	size_t i, end;
	size_t tval, val;
	int digit;

	buf = htbuf->buf;
	i = ref->off;
	end = i + ref->len;
	val = 0;
	for(; i < end; i++){
		digit = buf[i];
		if(digit >= '0' && digit <= '9')
			digit = digit - '0';
		else if(digit >= 'A' && digit <= 'F')
			digit = 10 + digit - 'A';
		else if(digit >= 'a' && digit <= 'f')
			digit = 10 + digit - 'a';
		else
			return -2;
		tval = val*16 + digit;
		if(tval < val)
			return -1;
		val = tval;
	}
	*valp = val;
	return 0;
}

static int
http5parse(Http5message *req)
{
	Http5ref *clref;
	Http5buf *htbuf;
	char *buf;
	size_t off, len;
	size_t keyoff, keylen, valueoff, valuelen;
	size_t firstoff, firstlen;
	size_t secondoff, secondlen;
	size_t thirdoff, thirdlen;
	int code;

	htbuf = &req->buf;
	buf = htbuf->buf;
	off = htbuf->off;
	len = htbuf->len;

	switch(req->state){
	case HTTP5_PARSE_LINE:
		req->state = HTTP5_PARSE_LINE;
		// skip any whitespace before method
		if(skipspace(buf, &off, len) == -1)
			return -1;

		firstoff = off;
		if(skipnonspace(buf, &off, len) == -1)
			return -1;
		firstlen = off - firstoff;

		// skip any whitespace before url
		if((code = skipspace(buf, &off, len)) < 0)
			return code;

		secondoff = off;
		if(skipnonspace(buf, &off, len) == -1)
			return -1;
		secondlen = off - secondoff;

		// skip any whitespace before version
		if((code = skipspace(buf, &off, len)) < 0)
			return code;

		thirdoff = off;
		if(skipvalue(buf, &off, len) == -1)
			return -1;
		thirdlen = off - thirdoff;

		if((code = skipendline(buf, &off, len)) < 0)
			return code;

		// store the method, resource and version.
		req->line[0] = (Http5ref){firstoff, firstlen};
		req->line[1] = (Http5ref){secondoff, secondlen};
		req->line[2] = (Http5ref){thirdoff, thirdlen};
		htbuf->off = off;
		// .. and fall through!
	case HTTP5_PARSE_HEADER:
		req->state = HTTP5_PARSE_HEADER;
		for(;;){
			// skip any whitespace before key
			if(skipspace(buf, &off, len) == -1)
				return -1;

			// empty line terminates header section (non-endline
			if((code = skipendline(buf, &off, len)) == -1)
				return -1;
			if(code == 0)
				goto parsebody;

			// skip until colon
			keyoff = off;
			if(skipkey(buf, &off, len) == -1)
				return -1;
			keylen = off - keyoff;

			if((code = skipchar(buf, &off, len, ':')) < 0)
				return code;

			// skip any whitespace preceding value
			if(skipspace(buf, &off, len) == -1)
				return -1;

			valueoff = off;
			if(skipvalue(buf, &off, len) == -1)
				return -1;
			valuelen = off - valueoff;

			if((code = skipendline(buf, &off, len)) < 0)
				return code;

			// store the header.
			if(req->nheaders >= nelem(req->headers))
				return -2;
			req->headers[req->nheaders] = (Http5header){
				(Http5ref){keyoff, keylen},
				(Http5ref){valueoff, valuelen}
			};
			http5tolower(htbuf, &req->headers[req->nheaders].key);
			req->nheaders++;
			htbuf->off = off;
		}
	parsebody:
		htbuf->off = off;
		req->state = HTTP5_PARSE_BODY;
		// check for the presence of a content-length header to determine whether there is a body or not.
		clref = http5header(req, "content-length");
		if(clref == NULL){
			clref = http5header(req, "transfer-encoding");
			if(clref == NULL){
				goto casedone;
			}
			if(http5cmp(clref, &req->buf, "chunked") == 0)
				goto casechunked;
			fprintf(stderr, "unknown transfer encoding\n");
			return -2;
		}
		req->body.off = off;
		if(http5number(htbuf, clref, &req->body.len) == -1)
			return -2;
		htbuf->off = off + req->body.len;
		if(htbuf->off < off || htbuf->off > htbuf->cap)
			return -2;
		return -1;
	case HTTP5_PARSE_BODY:
		if(htbuf->len >= htbuf->off)
			goto casedone;
		return -1;
	case HTTP5_PARSE_CHUNK:
	casechunked:
		req->state = HTTP5_PARSE_CHUNK;
		req->body.off = off;

		if((code = skiplength(buf, &off, len)) < 0)
			return code;
		req->body.len = off - req->body.off;
		skipvalue(buf, &off, len); // skip any possible chunk data
		if((code = skipendline(buf, &off, len)) < 0)
			return code;
		if(http5hex(htbuf, &req->body, &req->body.len) == -1)
			return -2;
		req->body.off = off;
		htbuf->off = off;
	case HTTP5_PARSE_CHUNK_BODY:
		req->state = HTTP5_PARSE_CHUNK_BODY;
		if(len < req->body.off + req->body.len)
			return -1;
		off = req->body.off + req->body.len;
		if((code = skipendline(buf, &off, len)) < 0)
			return code;
		htbuf->off = off;
	case HTTP5_DONE:
	casedone:
		req->state = HTTP5_DONE;
		return 0;
	}
	return -2;
}

void
http5clear(Http5message *msg)
{
	Http5buf *htbuf;
	htbuf = &msg->buf;
	msg->state = HTTP5_READY;
	msg->nheaders = 0;
	memmove(htbuf->buf, htbuf->buf+htbuf->off, htbuf->len - htbuf->off);
	htbuf->len -= htbuf->off;
	htbuf->off = 0;
}

static int
http5putchar(Http5buf *htbuf, int ch)
{
	if(htbuf->len + 1 > htbuf->cap)
		return -1;
	htbuf->buf[htbuf->len++] = ch;
	return 0;
}

static int
http5putstring(Http5ref *ref, Http5buf *htbuf, char *str)
{
	ref->off = htbuf->len;
	ref->len = strlen(str);
	if(htbuf->len + ref->len > htbuf->cap)
		return -1;
	memcpy(htbuf->buf + ref->off, str, ref->len);
	htbuf->len += ref->len;
	return 0;
}

static int
http5putdata(Http5ref *ref, Http5buf *htbuf, char *str, size_t len)
{
	ref->off = htbuf->len;
	ref->len = len;
	if(htbuf->len + ref->len > htbuf->cap)
		return -1;
	memcpy(htbuf->buf + ref->off, str, ref->len);
	htbuf->len += ref->len;
	return 0;
}

int
http5putheader(Http5message *resp, char *key, char *value)
{
	Http5header *hdr;
	Http5buf *htbuf;
	size_t nhdr;

	htbuf = &resp->buf;
	if((nhdr = resp->nheaders) >= nelem(resp->headers))
		return -1;
	hdr = resp->headers + nhdr;
	if(http5putstring(&hdr->key, htbuf, key) == -1)
		return -1;
	if(http5putchar(htbuf, ':') == -1)
		return -1;
	if(http5putchar(htbuf, ' ') == -1)
		return -1;
	if(http5putstring(&hdr->val, htbuf, value) == -1)
		return -1;
	if(http5putchar(htbuf, '\r') == -1)
		return -1;
	if(http5putchar(htbuf, '\n') == -1)
		return -1;
	resp->nheaders = nhdr+1;
	return 0;
}

int
http5putbody(Http5message *resp, char *body, size_t len)
{
	char num[32];
	Http5buf *htbuf;
	htbuf = &resp->buf;
	if(body != NULL && len > 0){
		snprintf(num, sizeof num, "%zd", len);
		if(http5putheader(resp, "content-length", num) == -1)
			return -1;
		}
	if(http5putchar(htbuf, '\r') == -1)
		return -1;
	if(http5putchar(htbuf, '\n') == -1)
		return -1;
	if(body != NULL && len > 0){
		if(http5putdata(&resp->body, htbuf, body, len) == -1)
			return -1;
	}
	return 0;
}

int
http5putline(Http5message *msg, char *first, char *second, char *third)
{
	Http5buf *htbuf;
	msg->type = HTTP5_TYPE_REQUEST;
	htbuf = &msg->buf;
	if(http5putstring(&msg->line[0], htbuf, first) == -1)
		return -1;
	if(http5putchar(htbuf, ' ') == -1)
		return -1;
	if(http5putstring(&msg->line[1], htbuf, second) == -1)
		return -1;
	if(http5putchar(htbuf, ' ') == -1)
		return -1;
	if(http5putstring(&msg->line[2], htbuf, third) == -1)
		return -1;
	if(http5putchar(htbuf, '\r') == -1)
		return -1;
	if(http5putchar(htbuf, '\n') == -1)
		return -1;
	return 0;
}

int
http5code(Http5message *resp, int code)
{
	size_t i;
	static struct {
		int code;
		char *scode;
		char *reason;
	} codes[] = {
		{100, "100", "Continue"},
		{101, "101", "Switching Protocols"},
		{102, "102", "Processing"},
		{200, "200", "OK"},
		{201, "201", "Created"},
		{202, "202", "Accepted"},
		{203, "203", "Non-Authoritative Information"},
		{204, "204", "No Content"},
		{205, "205", "Reset Content"},
		{206, "206", "Partial Content"},
		{207, "207", "Multi-Status"},
		{208, "208", "Already Reported"},
		{226, "226", "IM Used"},
		{300, "300", "Multiple Choices"},
		{301, "301", "Moved Permanently"},
		{302, "302", "Found"},
		{303, "303", "See Other"},
		{304, "304", "Not Modified"},
		{305, "305", "Use Proxy"},
		{306, "306", "(Unused)"},
		{307, "307", "Temporary Redirect"},
		{308, "308", "Permanent Redirect"},
		{400, "400", "Bad Request"},
		{401, "401", "Unauthorized"},
		{402, "402", "Payment Required"},
		{403, "403", "Forbidden"},
		{404, "404", "Not Found"},
		{405, "405", "Method Not Allowed"},
		{406, "406", "Not Acceptable"},
		{407, "407", "Proxy Authentication Required"},
		{408, "408", "Request Timeout"},
		{409, "409", "Conflict"},
		{410, "410", "Gone"},
		{411, "411", "Length Required"},
		{412, "412", "Precondition Failed"},
		{413, "413", "Payload Too Large"},
		{414, "414", "URI Too Long"},
		{415, "415", "Unsupported Media Type"},
		{416, "416", "Range Not Satisfiable"},
		{417, "417", "Expectation Failed"},
		{421, "421", "Misdirected Request"},
		{422, "422", "Unprocessable Entity"},
		{423, "423", "Locked"},
		{424, "424", "Failed Dependency"},
		{426, "426", "Upgrade Required"},
		{428, "428", "Precondition Required"},
		{429, "429", "Too Many Requests"},
		{431, "431", "Request Header Fields Too Large"},
		{451, "451", "Unavailable For Legal Reasons"},
		{500, "500", "Internal Server Error"},
		{501, "501", "Not Implemented"},
		{502, "502", "Bad Gateway"},
		{503, "503", "Service Unavailable"},
		{504, "504", "Gateway Timeout"},
		{505, "505", "HTTP Version Not Supported"},
		{506, "506", "Variant Also Negotiates"},
		{507, "507", "Insufficient Storage"},
		{508, "508", "Loop Detected"},
		{509, "509", "Unassigned"},
		{510, "510", "Not Extended"},
		{511, "511", "Network Authentication Required"},
	};
	for(i = 0; i < nelem(codes); i++)
		if(codes[i].code == code)
			break;
	if(i == nelem(codes))
		return -1;
	return http5putline(resp, "HTTP/1.1", codes[i].scode, codes[i].reason);
}

int
http5ok(Http5message *resp)
{
	return http5code(resp, 200);
}

void
http5read(Http5message *msg)
{
	msg->state = HTTP5_READY;
}

void
http5write(Http5message *msg)
{
	msg->state = HTTP5_WRITE;
}

void
http5close(Http5message *msg)
{
	msg->state = HTTP5_CLOSE;
}

static int
http5init(Http5chan *ht5, char *name, int (*handler)(void **statep, Http5message *, Http5message *), int incap, int outcap)
{
	memset(ht5, 0, sizeof ht5[0]);

	strncpy(ht5->name, name, sizeof ht5->name-1);
	ht5->name[sizeof ht5->name-1] = '\0';

	ht5->input.buf.cap = incap;
	ht5->output.buf.cap = outcap;

	ht5->input.buf.buf = malloc(ht5->input.buf.cap);
	if(ht5->input.buf.buf == NULL)
		return -1;

	ht5->output.buf.buf = malloc(ht5->output.buf.cap);
	if(ht5->output.buf.buf == NULL){
		free(ht5->output.buf.buf);
		return -1;
	}

	ht5->handler = handler;

	return 0;
}

static void
http5destroy(Http5chan *ht5)
{
	ht5->input.state = HTTP5_CLOSE;
	ht5->output.state = HTTP5_CLOSE;
	ht5->handler(&ht5->state, &ht5->output, &ht5->input);
	if(ht5->input.buf.buf)
		free(ht5->input.buf.buf);
	if(ht5->output.buf.buf)
		free(ht5->output.buf.buf);
}

static int
http5io(Http5chan *ht5, int fd, int flags)
{
	ssize_t nwr, nrd;
	int code;
	int rflags = 0;

	if(ht5->input.state == HTTP5_READY && ht5->output.state == HTTP5_READY)
		if(ht5->handler(&ht5->state, &ht5->output, &ht5->input) == -1)
			rflags |= HTTP5_PROCESS_ERROR;

	if(ht5->input.state != HTTP5_DONE && (flags & HTTP5_READ_READY) != 0){
		if(0)fputc('r', stderr);
		nrd = recv(fd, ht5->input.buf.buf + ht5->input.buf.len, ht5->input.buf.cap - ht5->input.buf.len, 0);
		if(nrd == -1){
			if(!wouldblock(sockerrno))
				rflags |= HTTP5_READ_ERROR;
		} else if(nrd == 0){
			rflags |= HTTP5_NORMAL_CLOSE;
		} else {
			ht5->input.buf.len += nrd;
		}

parsemore:
		if(ht5->input.buf.off < ht5->input.buf.len){
			code = http5parse(&ht5->input);
			if(code == -2){
				//Http5buf *inbuf = &ht5->input.buf;
				//fprintf(stderr, "paser error:%.*s--\n", (int)inbuf->len, inbuf->buf);
				rflags |= HTTP5_PROTOCOL_ERROR;
			}
			if(ht5->input.state == HTTP5_DONE){
				if(ht5->handler(&ht5->state, &ht5->output, &ht5->input) == -1)
					rflags |= HTTP5_PROCESS_ERROR;
				if(ht5->input.state != HTTP5_DONE && ht5->input.state != HTTP5_CLOSE)
					goto parsemore;
			}
		}
	}

	if(ht5->output.state != HTTP5_DONE && (flags & HTTP5_WRITE_READY) != 0){
		if(ht5->output.buf.len != ht5->output.buf.off){
			if(0)fputc('t', stderr);
			nwr = send(fd, ht5->output.buf.buf + ht5->output.buf.off, ht5->output.buf.len - ht5->output.buf.off, 0);
			if(nwr == -1){
				if(!wouldblock(sockerrno))
					rflags |= HTTP5_WRITE_ERROR;
			} else {
				ht5->output.buf.off += nwr;
				if(ht5->output.buf.off == ht5->output.buf.len){
					ht5->output.state = HTTP5_DONE;
					if(ht5->handler(&ht5->state, &ht5->output, &ht5->input) == -1)
						rflags |= HTTP5_PROCESS_ERROR;
				}
			}
		}
	}
	if(ht5->input.state != HTTP5_DONE && ht5->input.buf.len < ht5->input.buf.cap)
		rflags |= HTTP5_READ_READY;
	if(ht5->output.state != HTTP5_DONE && ht5->output.buf.off < ht5->output.buf.len)
		rflags |= HTTP5_WRITE_READY;
	if(ht5->output.state == HTTP5_CLOSE || ht5->input.state == HTTP5_CLOSE)
		rflags |= HTTP5_NORMAL_CLOSE;
	return rflags;
}

static struct http5state {
	struct sockaddr_in6 sa6;
	socklen_t salen;
	int wready;
	int fd;
	Http5chan ht5;
} *conns;

static int nconns;
static int aconns;
static int nactive;

int
http5connect(char *addr, int port, int incap, int outcap, int (*handler)(void **statep, Http5message *, Http5message *))
{
	struct http5state *conn;
	if(nconns == aconns){
		aconns = aconns == 0 ? 128 : aconns * 2;
		conns = realloc(conns, aconns * sizeof conns[0]);
	}
	conn = &conns[nconns];
	memset(conn, 0, sizeof conn[0]);
	conn->fd = -1;

	memset(&conn->sa6, 0, sizeof conn->sa6);
	conn->sa6.sin6_family = AF_INET6;
	if(inet_pton(AF_INET6, addr, &conn->sa6.sin6_addr) == -1){
		fprintf(stderr, "http5connect: inet_pton %s: %s\n", addr, strerror(sockerrno));
		goto error;
	}
	conn->sa6.sin6_port = htons(port);
	conn->salen = sizeof conn->sa6;

	if((conn->fd = socket(PF_INET6, SOCK_STREAM, IPPROTO_TCP)) == -1){
		fprintf(stderr, "http5connect: socket: %s\n", strerror(sockerrno));
		goto error;
	}

	int flag = 0;
	if(setsockopt(conn->fd, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&flag, sizeof flag) == -1){
		fprintf(stderr, "http5server: setsockopt ipv6only=%d: %s\n", flag, strerror(sockerrno));
		goto error;
	}

	flag = 1;
	if(ioctlsocket(conn->fd, FIONBIO, &flag) == -1){
		fprintf(stderr, "http5connect: failed to set non-blocking io: %s\n", strerror(sockerrno));
		goto error;
	}

	if(connect(conn->fd, (struct sockaddr *)&conn->sa6, conn->salen) == -1){
		int err = sockerrno;
		if(!wouldblock(err)){
			fprintf(stderr, "http5connect: connect: %s: %d\n", strerror(err), err);
			goto error;
		}
	}

	if(http5init(&conn->ht5, addr, handler, incap, outcap) == -1){
		fprintf(stderr, "http5server: failed to initialize http connection\n");
		goto error;
	}
	nconns++;
	return 0;
error:
	if(conn->fd != -1)
		closesocket(conn->fd);
	conn->fd = -1;
	return -1;
}

int
http5server(int port, int incap, int outcap, int (*handler)(void **statep, Http5message *, Http5message *))
{
	struct http5state *conn;
	struct sockaddr_in6 sa;
	fd_set rset0, wset0, rset1, wset1;
	fd_set *rset, *wset, *nextrset, *nextwset;
	fd_set *tmpset;

	int lfd, nfd, maxfd;
	int i, j;

	nfd = -1;
	if((lfd = socket(PF_INET6, SOCK_STREAM, IPPROTO_TCP)) == -1){
		fprintf(stderr, "http5server: socket: %s\n", strerror(sockerrno));
		goto error;
	}

	int flag = 1;
	if(setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, (void *)&flag, sizeof flag) == -1){
		fprintf(stderr, "http5server: setsockopt reuseaddr=%d: %s\n", flag, strerror(sockerrno));
		goto error;
	}

	flag = 0;
	if(setsockopt(lfd, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&flag, sizeof flag) == -1){
		fprintf(stderr, "http5server: setsockopt ipv6only=%d: %s\n", flag, strerror(sockerrno));
		goto error;
	}

	memset(&sa, 0, sizeof sa);
	sa.sin6_family = AF_INET6;
	sa.sin6_port = htons(port);
	sa.sin6_addr = in6addr_any;
	if(bind(lfd, (struct sockaddr*)&sa, sizeof sa) == -1){
		fprintf(stderr, "http5server: bind: %s\n", strerror(sockerrno));
		goto error;
	}

	if(listen(lfd, 1000) == -1){
		fprintf(stderr, "http5server: listen: %s\n", strerror(sockerrno));
		goto error;
	}

	FD_ZERO(&rset0);
	FD_ZERO(&wset0);
	FD_ZERO(&rset1);
	FD_ZERO(&wset1);
	rset = &rset0;
	wset = &wset0;
	nextrset = &rset1;
	nextwset = &wset1;

	FD_SET(lfd, rset);
	for(i = 0; i < nconns; i++){
		if(conns[i].fd != -1){
			maxfd = maxfd > conns[i].fd ? maxfd : conns[i].fd;
			if(!conns[i].wready)
				FD_SET(conns[i].fd, wset);
		}
	}

	for(;;){
		if(0)fputc('s', stderr);
		select(maxfd+1, rset, wset, NULL, NULL);
		if(FD_ISSET(lfd, rset)){
			if(nconns == aconns){
				aconns = aconns == 0 ? 128 : aconns * 2;
				conns = realloc(conns, aconns * sizeof conns[0]);
			}
			conn = &conns[nconns];
			memset(conn, 0, sizeof conn[0]);
			conn->salen = sizeof conn->sa6;
			if(0)fputc('a', stderr);
			conn->fd = accept(lfd, (struct sockaddr *)&conn->sa6, &conn->salen);
			if(conn->fd != -1){
				char name[128];
				struct sockaddr_in6 *sa6 = &conn->sa6;
				size_t portoff;
				name[0] = '[';
				inet_ntop(sa6->sin6_family, &sa6->sin6_addr, name+1, sizeof name-1);
				portoff = strlen(name);
				snprintf(name+portoff, sizeof name-portoff, "]:%d", sa6->sin6_port);
				flag = 1;
				if(ioctlsocket(conn->fd, FIONBIO, &flag) == -1){
					fprintf(stderr, "http5server: failed to set non-blocking io: %s\n", strerror(sockerrno));
					closesocket(conn->fd);
					conn->fd = -1;
					goto next;
				}
				if(http5init(&conn->ht5, name, handler, incap, outcap) == -1){
					fprintf(stderr, "http5server: failed to initialize http connection\n");
					closesocket(conn->fd);
					goto next;
				}
				fprintf(stderr, "accepted %s\n", name);
				nconns++;
				// this is cheating a little, but can save a select round if we are lucky.
				//FD_SET(conn->fd, rset);
				//FD_SET(conn->fd, wset);
			}
		}
next:
		//FD_ZERO(nextrset);
		//FD_ZERO(nextwset);
		FD_SET(lfd, nextrset);
		maxfd = lfd;
		nactive = 0;
		for(i = 0; i < nconns; i++){
			if(conns[i].fd != -1){
				nactive++;
				int flags = 0;
				if(FD_ISSET(conns[i].fd, rset))
					flags |= HTTP5_READ_READY;
				if(conns[i].wready || FD_ISSET(conns[i].fd, wset)){
					conns[i].wready = 1;
					flags |= HTTP5_WRITE_READY;
				}
				flags = http5io(&conns[i].ht5, conns[i].fd, flags);
				if((flags & HTTP5_ERROR_MASK) != 0){
					FD_CLR(conns[i].fd, rset);
					FD_CLR(conns[i].fd, wset);
					FD_CLR(conns[i].fd, nextrset);
					FD_CLR(conns[i].fd, nextwset);
					if((flags & HTTP5_ERROR_MASK) != HTTP5_NORMAL_CLOSE)
						fprintf(stderr, "http5server: error from http5io: flags 0x%x, closing.\n", flags & HTTP5_ERROR_MASK);
					closesocket(conns[i].fd);
					http5destroy(&conns[i].ht5);
					conns[i].fd = -1;
				} else {
					if((flags & HTTP5_READ_READY) != 0){
						FD_SET(conns[i].fd, nextrset);
						maxfd = maxfd > conns[i].fd ? maxfd : conns[i].fd;
					} else {
						FD_CLR(conns[i].fd, nextrset);
					}
					if(conns[i].wready == 0 || (flags & HTTP5_WRITE_READY) != 0){
						FD_SET(conns[i].fd, nextwset);
						maxfd = maxfd > conns[i].fd ? maxfd : conns[i].fd;
						conns[i].wready = 0;
					} else {
						FD_CLR(conns[i].fd, nextwset);
					}
				}
			}
		}
		if(nactive < nconns/2){
			j = 0;
			for(i = 0; i < nconns; i++){
				if(conns[i].fd != -1){
					memcpy(conns + j, conns + i, sizeof conns[0]);
					j++;
				}
			}
			nconns = j;
		}

		tmpset = rset;
		rset = nextrset;
		nextrset = tmpset;

		tmpset = wset;
		wset = nextwset;
		nextwset = tmpset;
	}

error:
	if(lfd != -1)
		closesocket(lfd);
	if(nfd != -1)
		closesocket(nfd);
	return -1;
}
