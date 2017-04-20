
http5: main.o http5.o
	$(CC) $(LDFLAGS) -o $@ main.o http5.o

clean:
	rm -f http5 *.o
