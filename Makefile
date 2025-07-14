.POSIX:

include config.mk

config.h: config.def.h
	cp $^ $@

clean:
	rm -f config.h

.PHONY:
	clean
