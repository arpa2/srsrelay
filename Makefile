all: srsrelay

srsrelay: srsrelay.c
	# gcc -o $@ $< -lsrs2
	gcc -ggdb3 -o $@ $< /usr/local/lib/libsrs2.a

clean:
	rm -f srsrelay

anew: clean all
