
#include <stdio.h>
#include <winsock2.h>

#define nelem(x) (sizeof(x)/sizeof(x[0]))

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
	HTTP5_ERROR_MASK = HTTP5_READ_ERROR | HTTP5_READ_EOF | HTTP5_WRITE_ERROR | HTTP5_PROTOCOL_ERROR,

	HTTP5_PARSE_REQUEST = 0,
	HTTP5_PARSE_HEADER = 1,
	HTTP5_PARSE_BODY = 2,
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
	int off = *offp;
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
	int off = *offp;
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
	int off = *offp;
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
	int off = *offp;
	while(off < len && isvaluechar(buf[off]))
		off++;
	if(off == len)
		return -1;
	*offp = off;
	return 0;
}

static int
skipendline(char *buf, size_t *offp, size_t len)
{
	int off = *offp;
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
	for(; i < end; i++)
		buf[i] = tolower(buf[i]);
}

static int
http5cmp(Http5ref *ref, Http5buf *htbuf, char *key)
{
	size_t keylen;
	keylen = strlen(key);
	keylen = keylen < ref->len ? keylen : ref->len;
	return memcmp(htbuf->buf + ref->off, key, keylen);
}

static Http5ref *
http5header(Http5request *req, Http5buf *htbuf, char *key)
{
	char *buf;
	size_t i, keylen;

	keylen = strlen(key);
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
	return val;
}

static int
http5parse(Http5request *req, Http5buf *htbuf)
{
	Http5ref *clref;
	char *buf;
	size_t off, len;
	size_t keyoff, keylen, valueoff, valuelen;
	size_t methodoff, methodlen;
	size_t resourceoff, resourcelen;
	size_t versionoff, versionlen;
	int code, ch;


	buf = htbuf->buf;
	off = htbuf->off;
	len = htbuf->len;

	switch(req->state){
	case HTTP5_PARSE_REQUEST:
		req->state = HTTP5_PARSE_REQUEST;
		// skip any whitespace before method
		if(skipspace(buf, &off, len) == -1)
			return -1;

		methodoff = off;
		if(skipnonspace(buf, &off, len) == -1)
			return -1;
		methodlen = off - methodoff;

		// skip any whitespace before url
		if((code = skipspace(buf, &off, len)) < 0)
			return code;

		resourceoff = off;
		if(skipnonspace(buf, &off, len) == -1)
			return -1;
		resourcelen = off - resourceoff;

		// skip any whitespace before version
		if((code = skipspace(buf, &off, len)) < 0)
			return code;

		versionoff = off;
		if(skipnonspace(buf, &off, len) == -1)
			return -1;
		versionlen = off - versionoff;

		if((code = skipendline(buf, &off, len)) < 0)
			return code;

		// store the method, resource and version.
		req->method = (Http5ref){methodoff, methodlen};
		req->resource = (Http5ref){resourceoff, resourcelen};
		req->version = (Http5ref){versionoff, versionlen};
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

			// empty line terminates header section.
			if((code = skipendline(buf, &off, len)) == -1)
				return code;
			if(code == 0)
				goto parsebody;

			// skip until colon
			keyoff = off;
			if(skipkey(buf, &off, len) == -1)
				return -1;
			// ensure it is a colon
			if(buf[off] != ':')
				return -2;
			keylen = off - keyoff;
			off++;

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
		clref = http5header(req, htbuf, "content-length");
		if(clref == NULL){
			if(http5header(req, htbuf, "transfer-encoding") != NULL)
				return -2;
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
	}
	return -2;
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

static int
http5putheader(Http5response *resp, Http5buf *htbuf, char *key, char *value)
{
	Http5header *hdr;
	size_t nhdr;

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

static int
http5putbody(Http5response *resp, Http5buf *htbuf, char *body, size_t len)
{
	char num[32];
	snprintf(num, sizeof num, "%zd", len);
	if(http5putheader(resp, htbuf, "content-length", num) == -1)
		return -1;
	if(http5putchar(htbuf, '\r') == -1)
		return -1;
	if(http5putchar(htbuf, '\n') == -1)
		return -1;
	if(http5putdata(&resp->body, htbuf, body, len) == -1)
		return -1;
	return 0;
}

static int
http5respond(Http5response *resp, Http5buf *htbuf)
{
	if(http5putstring(&resp->version, htbuf, "HTTP/1.1") == -1)
		return -1;
	if(http5putchar(htbuf, ' ') == -1)
		return -1;
	if(http5putstring(&resp->code, htbuf, "200") == -1)
		return -1;
	if(http5putchar(htbuf, ' ') == -1)
		return -1;
	if(http5putstring(&resp->reason, htbuf, "OK") == -1)
		return -1;
	if(http5putchar(htbuf, '\r') == -1)
		return -1;
	if(http5putchar(htbuf, '\n') == -1)
		return -1;
	return 0;	
}


static int
http5process(Http5response *resp, Http5buf *outbuf, Http5request *req, Http5buf *inbuf)
{
	size_t i;
	fprintf(stderr, "http5 process\n");
	fprintf(stderr, "method: %.*s\n", (int)req->method.len, inbuf->buf + req->method.off);
	fprintf(stderr, "resource: %.*s\n", (int)req->resource.len, inbuf->buf + req->resource.off);
	fprintf(stderr, "version: %.*s\n", (int)req->version.len, inbuf->buf + req->version.off);

	for(i = 0; i < req->nheaders; i++){
		fprintf(stderr, "%.*s: %.*s\n",
			(int)req->headers[i].key.len, inbuf->buf + req->headers[i].key.off,
			(int)req->headers[i].val.len, inbuf->buf + req->headers[i].val.off
		);
	}

	if(http5respond(resp, outbuf) == -1)
		return -1;
	if(http5putheader(resp, outbuf, "content-type", "text/plain") == -1)
		return -1;
	char *body = "hello world\n";
	if(http5putbody(resp, outbuf, body, strlen(body)) == -1)
		return -1;
	return 0;
}

static int
http5init(Http5 *ht5, int incap, int outcap)
{
	memset(ht5, 0, sizeof ht5[0]);

	ht5->input.cap = incap;
	ht5->output.cap = outcap;

	ht5->input.buf = malloc(ht5->input.cap);
	if(ht5->input.buf == NULL)
		return -1;

	ht5->output.buf = malloc(ht5->output.cap);
	if(ht5->output.buf == NULL){
		free(ht5->input.buf);
		return -1;
	}

	return 0;
}

static int
http5io(Http5 *ht5, int fd, int flags)
{
	size_t nwr, nrd;
	int code;
	int rflags = 0;

	if((flags & HTTP5_READ_READY) != 0){
		nrd = recv(fd, ht5->input.buf + ht5->input.len, ht5->input.cap - ht5->input.len, 0);
		if(nrd == -1)
			rflags |= HTTP5_READ_ERROR;
		else if(nrd == 0)
			rflags |= HTTP5_READ_EOF;
		else
			ht5->input.len += nrd;
	}

	code = http5parse(&ht5->req, &ht5->input);
	if(code == -2)
		rflags |= HTTP5_PROTOCOL_ERROR;
	if(code == 0){
		if(http5process(&ht5->resp, &ht5->output, &ht5->req, &ht5->input) == -1)
			rflags |= HTTP5_PROTOCOL_ERROR;
	}

	if(ht5->output.off < ht5->output.len && (flags & HTTP5_WRITE_READY) != 0){
		nwr = send(fd, ht5->output.buf + ht5->output.off, ht5->output.len - ht5->output.off, 0);
		fprintf(stderr, "http5io: wrote %zd:\n", nwr);
		fprintf(stderr, "%.*s\n", ht5->output.len - ht5->output.off, ht5->output.buf + ht5->output.off);
		if(nwr == -1)
			rflags |= HTTP5_WRITE_ERROR;
		else
			ht5->output.off += nwr;
	}

	if(ht5->output.len < ht5->output.cap && ht5->input.len < ht5->input.cap)
		rflags |= HTTP5_READ_READY;
	if(ht5->output.off < ht5->output.len)
		rflags |= HTTP5_WRITE_READY;
	return rflags;
}

int
http5server(int port, int incap, int outcap)
{
	struct sockaddr_in sa;
	fd_set rset0, wset0, rset1, wset1;
	fd_set *rset, *wset, *nextrset, *nextwset;
	fd_set *tmpset;
	struct {
		char name[64];
		struct sockaddr sa;
		int salen;
		int wready;
		int fd;
		Http5 ht5;
	} *conns, *conn;
	int nconns, aconns, nactive;
	int lfd, nfd, maxfd;
	int i, j;

	nconns = 0;
	aconns = 0;
	conns = NULL;

	nfd = -1;
	if((lfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1){
		fprintf(stderr, "http5server: socket: %s\n", strerror(errno));
		goto error;
	}

	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr.s_addr = htonl(INADDR_ANY);
	if(bind(lfd, (struct sockaddr*)&sa, sizeof sa) == -1){
		fprintf(stderr, "http5server: bind: %s\n", strerror(errno));
		goto error;
	}

	if(listen(lfd, 100) == -1){
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
			fprintf(stderr, "accepted from: %s\n", conn->name);
			if(conn->fd != -1){
				int nonblock = 1;
				if(ioctlsocket(conn->fd, FIONBIO, &nonblock) == -1){
					fprintf(stderr, "http5server: failed to set non-blocking io: %s\n", strerror(errno));
					closesocket(conn->fd);
					conn->fd = -1;
					goto next;
				}
				if(http5init(&conn->ht5, incap, outcap) == -1){
					fprintf(stderr, "http5server: failed to initialize http connection\n");
					closesocket(conn->fd);
					goto next;
				}
				nconns++;
			}
		}
next:
		FD_ZERO(nextrset);
		FD_ZERO(nextwset);
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
					fprintf(stderr, "http5server: error from http5io: closing\n");
					closesocket(conns[i].fd);
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

int
main(int argc, char *argv[])
{
	WSADATA wsadata;
	int port = 5555;
	if(WSAStartup(MAKEWORD(2,2), &wsadata) != 0){
		fprintf(stderr, "winsock initialization failed\n");
		exit(1);
	}
	if(argc > 1)
		port = strtol(argv[1], NULL, 10);
	return http5server(port, 8192, 8192);
}
