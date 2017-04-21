# the following is truly awful, but it allows having
# one makefile for both win32 and unix
# the "trick" is using backslash line continuations
# in comments, which are supported by gnu make but not nmake
# while using the !ifndef conditional of nmake. awful, i know.
# \
!ifndef 0 # \
CFLAGS=/Ox /Oy # \
RM=del # \
O=obj # \
LIBS=ws2_32.lib # \
all: main.exe #\
!else

all: http5.exe
RM=rm -f
O=o
LIBS=-lm

# \
!endif

HFILES=\
	os.h\
	http5.h\

OFILES=\
	main.$(O)\
	http5.$(O)\

main.exe: $(OFILES)
	$(CC) $(LDFLAGS) $(OFILES) /link $(LIBS)

http5: $(OFILES)
	$(CC) $(LDFLAGS) -o $@ $(OFILES)

clean:
	$(RM) http5 main.exe *.$(O)
