.POSIX:

include config.mk

BIN = prometheus

$(BIN): config.h prometheus.c
	$(CC) $(CFLAGS) -o $@ prometheus.c

config.h: config.def.h
	cp $^ $@

clean:
	rm -f $(BIN) config.h

.PHONY:
	clean
