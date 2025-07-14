.POSIX:

include config.mk

config.h: config.def.h
	cp $^ $@
