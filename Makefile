.POSIX:

include config.mk

SRCS = prometheus.c sha256.c
BIN = prometheus

OBJS = $(SRCS:.c=.o)

all: $(BIN)

$(BIN): $(OBJS) config.h
	$(CC) -o $@ $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $^

config.h: config.def.h
	cp $^ $@

install: all
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	cp -f $(BIN) $(DESTDIR)$(PREFIX)/bin
	mkdir -p $(DESTDIR)$(MANPREFIX)/man1
	cp -f $(BIN).1 $(DESTDIR)$(MANPREFIX)/man1

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(BIN)
	rm -f $(DESTDIR)$(MANPREFIX)/man1/$(BIN).1

clean:
	rm -f $(BIN) config.h

.PHONY:
	clean install uninstall
