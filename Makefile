include config.mk

SRCS = pr.c sha256.c
OUT = pr

OBJS = $(SRCS:.c=.o)

.PHONY: clean install uninstall

all: $(OUT)

clean:
	rm -f $(OUT) $(OBJS) config.h

install: all
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	cp -f $(BIN) $(DESTDIR)$(PREFIX)/bin
	mkdir -p $(DESTDIR)$(MANPREFIX)/man1
	cp -f $(BIN).1 $(DESTDIR)$(MANPREFIX)/man1

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(BIN)
	rm -f $(DESTDIR)$(MANPREFIX)/man1/$(BIN).1

$(OUT): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS) $(LIBS)

config.h: config.def.h
	cp $^ $@

%.o: %.c config.h
	$(CC) $(CFLAGS) -o $@ -c $<
