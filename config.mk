PREFIX = /usr/local
MANPREFIX = $(PREFIX)/share/man

CC = cc
CFLAGS = -std=c99 -Wall -Wextra -Wpedantic
LDFLAGS = -s
LIBS = -lcurl
