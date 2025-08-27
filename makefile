include config.mk

OBJS = pr.o sha256.o
OUT  = pr

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
	$(LD) $(LDFLAGS) -e main -o $@ $^ $(LIBS)

config.h: config.def.h
	cp $^ $@

$(OBJS): config.h
	$(CC) $(CFLAGS) -c -o $@ $(@:.o=.c)
