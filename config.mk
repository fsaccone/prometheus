PREFIX = /usr/local
MANPREFIX = $(PREFIX)/share/man

CC = cc
LD = ld
CFLAGS = -std=c99 -Wall -Wextra -Wpedantic
LDFLAGS = -s
LIBS = -lssl -lcrypto
