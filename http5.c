
#include "os.h"
#include "http5.h"

typedef struct Http5 Http5;

struct Http5 {
	Http5message req;
	Http5message resp;
	int (*handler)(Http5message *, Http5message *);
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

//fprintf(stderr, "http5parse:\n%.*s\n--\n", htbuf->len, htbuf->buf);

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
		req->method = (Http5ref){firstoff, firstlen};
		req->resource = (Http5ref){secondoff, secondlen};
		req->version = (Http5ref){thirdoff, thirdlen};
		htbuf->off = off;
		http5tolower(htbuf, &req->method);
		http5tolower(htbuf, &req->version);
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
		// check for the presence of a content-length header to determine whether there is a body or not.
		clref = http5header(req, "content-length");
		if(clref == NULL){
			if(http5header(req, "transfer-encoding") != NULL)
				return -2;
			htbuf->off = off;
			return 0;
		}
		req->body.off = off;
		if(http5number(htbuf, clref, &req->body.len) == -1)
			return -2;
		htbuf->off = off + req->body.len;
		if(htbuf->off < off || htbuf->off > htbuf->cap)
			return -2;
	case HTTP5_PARSE_BODY:
		req->state = HTTP5_PARSE_BODY;
		if(htbuf->len >= htbuf->off)
			return 0;
		return -1;
	case HTTP5_FLUSH_OUTPUT:
		return 0;
	}
	return -2;
}

static int
http5requestdone(Http5message *req)
{
	Http5buf *htbuf;
	htbuf = &req->buf;
	req->nheaders = 0;
	memmove(htbuf->buf, htbuf->buf+htbuf->off, htbuf->len - htbuf->off);
	htbuf->len -= htbuf->off;
	htbuf->off = 0;
	return 0;
}

static int
http5responsedone(Http5message *resp)
{
	Http5buf *htbuf;
	htbuf = &resp->buf;
	resp->nheaders = 0;
	htbuf->len -= htbuf->off;
	htbuf->off = 0;
	return 0;
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
	snprintf(num, sizeof num, "%zd", len);
	if(http5putheader(resp, "content-length", num) == -1)
		return -1;
	if(http5putchar(htbuf, '\r') == -1)
		return -1;
	if(http5putchar(htbuf, '\n') == -1)
		return -1;
	if(http5putdata(&resp->body, htbuf, body, len) == -1)
		return -1;
	return 0;
}

int
http5respond(Http5message *resp, char *version, char *code, char *reason)
{
	Http5buf *htbuf;
	resp->type = HTTP5_TYPE_RESPONSE;
	htbuf = &resp->buf;
	if(http5putstring(&resp->version, htbuf, version) == -1)
		return -1;
	if(http5putchar(htbuf, ' ') == -1)
		return -1;
	if(http5putstring(&resp->code, htbuf, code) == -1)
		return -1;
	if(http5putchar(htbuf, ' ') == -1)
		return -1;
	if(http5putstring(&resp->reason, htbuf, reason) == -1)
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
	return http5respond(resp, "HTTP/1.1", codes[i].scode, codes[i].reason);
}

int
http5ok(Http5message *resp)
{
	return http5code(resp, 200);
}

int
http5request(Http5message *req, char *method, char *resource, char *version)
{
	Http5buf *htbuf;
	req->type = HTTP5_TYPE_REQUEST;
	htbuf = &req->buf;
	if(http5putstring(&req->method, htbuf, method) == -1)
		return -1;
	if(http5putchar(htbuf, ' ') == -1)
		return -1;
	if(http5putstring(&req->resource, htbuf, resource) == -1)
		return -1;
	if(http5putchar(htbuf, ' ') == -1)
		return -1;
	if(http5putstring(&req->version, htbuf, version) == -1)
		return -1;
	if(http5putchar(htbuf, '\r') == -1)
		return -1;
	if(http5putchar(htbuf, '\n') == -1)
		return -1;
	return 0;
}

static int
http5init(Http5 *ht5, int (*handler)(Http5message *, Http5message *), int incap, int outcap)
{
	memset(ht5, 0, sizeof ht5[0]);

	ht5->req.buf.cap = incap;
	ht5->resp.buf.cap = outcap;

	ht5->req.buf.buf = malloc(ht5->req.buf.cap);
	if(ht5->req.buf.buf == NULL)
		return -1;

	ht5->resp.buf.buf = malloc(ht5->resp.buf.cap);
	if(ht5->resp.buf.buf == NULL){
		free(ht5->resp.buf.buf);
		return -1;
	}

	ht5->handler = handler;

	return 0;
}

static void
http5destroy(Http5 *ht5)
{
	if(ht5->req.buf.buf)
		free(ht5->req.buf.buf);
	if(ht5->resp.buf.buf)
		free(ht5->resp.buf.buf);
}

static int
http5io(Http5 *ht5, int fd, int flags)
{
	ssize_t nwr, nrd;
	int code;
	int rflags = 0;

	if((flags & HTTP5_READ_READY) != 0){
		nrd = recv(fd, ht5->req.buf.buf + ht5->req.buf.len, ht5->req.buf.cap - ht5->req.buf.len, 0);
		if(nrd == -1){
			if(errno != EAGAIN)
				rflags |= HTTP5_READ_ERROR;
		} else if(nrd == 0){
			rflags |= HTTP5_READ_EOF;
		} else {
			ht5->req.buf.len += nrd;
		}
	}

	if(ht5->req.state != HTTP5_FLUSH_OUTPUT && ht5->req.buf.off < ht5->req.buf.len){
		code = http5parse(&ht5->req);
		if(code == -2)
			rflags |= HTTP5_PROTOCOL_ERROR;
		if(code == 0){
			if(ht5->handler(&ht5->resp, &ht5->req) == -1)
				rflags |= HTTP5_PROCESS_ERROR;
		}
	}

	if(ht5->resp.buf.off < ht5->resp.buf.len && (flags & HTTP5_WRITE_READY) != 0){
		nwr = send(fd, ht5->resp.buf.buf + ht5->resp.buf.off, ht5->resp.buf.len - ht5->resp.buf.off, 0);
		if(nwr == -1){
			if(errno != EAGAIN)
				rflags |= HTTP5_WRITE_ERROR;
		} else {
			ht5->resp.buf.off += nwr;
		}
	}

	if(ht5->resp.buf.len < ht5->resp.buf.cap && ht5->req.buf.len < ht5->req.buf.cap)
		rflags |= HTTP5_READ_READY;
	if(ht5->resp.buf.off < ht5->resp.buf.len)
		rflags |= HTTP5_WRITE_READY;
	if(ht5->req.state == HTTP5_FLUSH_OUTPUT && ht5->resp.buf.off == ht5->resp.buf.len){
		ht5->req.state = 0;
		if(http5cmp(&ht5->req.version, &ht5->req.buf, "http/1.0") == 0)
			if(http5cmp(http5header(&ht5->req, "connection"), &ht5->req.buf, "keep-alive") != 0)
				rflags |= HTTP5_READ_EOF;
		if(http5cmp(&ht5->req.version, &ht5->req.buf, "http/1.1") == 0)
			if(http5cmp(http5header(&ht5->req, "connection"), &ht5->req.buf, "close") == 0)
				rflags |= HTTP5_READ_EOF;
		http5requestdone(&ht5->req);
		http5responsedone(&ht5->resp);
	}
	return rflags;
}

static struct http5state {
	char name[64];
	struct sockaddr sa;
	socklen_t salen;
	int wready;
	int fd;
	Http5 ht5;
} *conns;

static int nconns;
static int aconns;
static int nactive;

int
http5connect(char *addr, int port, int incap, int outcap, int (*handler)(Http5message *, Http5message *))
{
	struct http5state *conn;
	if(nconns == aconns){
		aconns = aconns == 0 ? 128 : aconns * 2;
		conns = realloc(conns, aconns * sizeof conns[0]);
	}
	conn = &conns[nconns];
	memset(conn, 0, sizeof conn[0]);
	conn->fd = -1;

	if(inet_pton(AF_INET, addr, &conn->sa) == -1){
		fprintf(stderr, "http5connect: inet_pton %s: %s\n", addr, strerror(errno));
		goto error;
	}
	((struct sockaddr_in *)&conn->sa)->sin_port = htons(port);
	conn->salen = sizeof(struct sockaddr_in);

	if((conn->fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1){
		fprintf(stderr, "http5connect: socket: %s\n", strerror(errno));
		goto error;
	}

	if(connect(conn->fd, &conn->sa, conn->salen) == -1){
		fprintf(stderr, "http5connect: connect: %s\n", strerror(errno));
		goto error;
	}

	int nonblock = 1;
	if(ioctlsocket(conn->fd, FIONBIO, &nonblock) == -1){
		fprintf(stderr, "http5connect: failed to set non-blocking io: %s\n", strerror(errno));
		goto error;
	}
	if(http5init(&conn->ht5, handler, incap, outcap) == -1){
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
http5server(int port, int incap, int outcap, int (*handler)(Http5message *, Http5message *))
{
	struct http5state *conn;
	struct sockaddr_in sa;
	fd_set rset0, wset0, rset1, wset1;
	fd_set *rset, *wset, *nextrset, *nextwset;
	fd_set *tmpset;

	int lfd, nfd, maxfd;
	int i, j;

	nfd = -1;
	if((lfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1){
		fprintf(stderr, "http5server: socket: %s\n", strerror(errno));
		goto error;
	}

	int flag = 1;
	if(setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, (void *)&flag, sizeof flag) == -1){
		fprintf(stderr, "http5server: setsockopt: %s\n", strerror(errno));
		goto error;
	}

	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr.s_addr = htonl(INADDR_ANY);
	if(bind(lfd, (struct sockaddr*)&sa, sizeof sa) == -1){
		fprintf(stderr, "http5server: bind: %s\n", strerror(errno));
		goto error;
	}

	if(listen(lfd, 1000) == -1){
		fprintf(stderr, "http5server: listen: %s\n", strerror(errno));
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
	maxfd = lfd;
	for(;;){
		select(maxfd+1, rset, wset, NULL, NULL);
		if(FD_ISSET(lfd, rset)){
			if(nconns == aconns){
				aconns = aconns == 0 ? 128 : aconns * 2;
				conns = realloc(conns, aconns * sizeof conns[0]);
			}
			conn = &conns[nconns];
			memset(conn, 0, sizeof conn[0]);
			conn->salen = sizeof conn->sa;
			conn->fd = accept(lfd, &conn->sa, &conn->salen);
			if(conn->sa.sa_family == AF_INET){
				struct sockaddr_in *sa4 = (struct sockaddr_in*)&conn->sa;
				size_t portoff;
				inet_ntop(sa4->sin_family, &sa4->sin_addr.s_addr, conn->name, sizeof conn->name);
				portoff = strlen(conn->name);
				snprintf(conn->name+portoff, sizeof conn->name-portoff, ":%d", sa4->sin_port);
			} else {
				fprintf(stderr, "unsupported address family\n");
				goto next;
			}
			if(conn->fd != -1){
				int nonblock = 1;
				if(ioctlsocket(conn->fd, FIONBIO, &nonblock) == -1){
					fprintf(stderr, "http5server: failed to set non-blocking io: %s\n", strerror(errno));
					closesocket(conn->fd);
					conn->fd = -1;
					goto next;
				}
				if(http5init(&conn->ht5, handler, incap, outcap) == -1){
					fprintf(stderr, "http5server: failed to initialize http connection\n");
					closesocket(conn->fd);
					goto next;
				}
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
					if((flags & HTTP5_ERROR_MASK) != HTTP5_READ_EOF)
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
