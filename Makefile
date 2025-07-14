.POSIX:

include config.mk

BIN = prometheus

all: $(BIN)

$(BIN): config.h prometheus.c
	$(CC) $(CFLAGS) -o $@ prometheus.c

config.h: config.def.h
	cp $^ $@

install: all
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	cp -f $(BIN) $(DESTDIR)$(PREFIX)/bin

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(BIN)

clean:
	rm -f $(BIN) config.h

.PHONY:
	clean install uninstall
