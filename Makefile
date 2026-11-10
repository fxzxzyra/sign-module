CC = gcc
PKG_CONFIG ?= pkg-config
CPPFLAGS += -Isrc/include -DOPENSSL_API_COMPAT=40000 -DOPENSSL_NO_DEPRECATED $(shell $(PKG_CONFIG) --cflags libcrypto liblzma)
CFLAGS ?= -std=c23 -O2 -flto -ffunction-sections -fdata-sections -Wall -Wextra -Wpedantic
LDFLAGS ?= -flto -s -Wl,--gc-sections
LIBS = $(shell $(PKG_CONFIG) --libs libcrypto liblzma)
TARGET = sign-module
SOURCE = src/sign-module.c
DISTDIR = dist

.PHONY: all clean check-deps

all: $(DISTDIR)/$(TARGET)

check-deps:
	@$(PKG_CONFIG) --print-errors --exists 'libcrypto >= 4.0' 'liblzma >= 5.4'

$(DISTDIR)/$(TARGET): $(SOURCE) src/include/linux/module_signature.h Makefile | check-deps $(DISTDIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SOURCE) $(LDFLAGS) -o $@ $(LIBS)

$(DISTDIR):
	mkdir -p $(DISTDIR)

clean:
	rm -rf $(DISTDIR)
