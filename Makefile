CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Wformat -Wformat-security -O2 -fstack-protector-strong
CPPFLAGS += -Iinclude

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

UNAME_S := $(shell uname -s)

# --- Dependency discovery -----------------------------------------------------
# On macOS use Homebrew prefixes when available; otherwise fall back to
# /usr/local. On Linux assume system include paths plus /usr/local/lib.
ifeq ($(UNAME_S),Darwin)
    BREW := $(shell command -v brew 2>/dev/null)
    ifneq ($(BREW),)
        OPENSSL_PREFIX ?= $(shell brew --prefix openssl@3 2>/dev/null)
        LIBOQS_PREFIX  ?= $(shell brew --prefix liboqs 2>/dev/null)
    endif
    OPENSSL_PREFIX ?= /usr/local/opt/openssl@3
    LIBOQS_PREFIX  ?= /usr/local
    CPPFLAGS += -I$(OPENSSL_PREFIX)/include -I$(LIBOQS_PREFIX)/include
    LDFLAGS  += -L$(OPENSSL_PREFIX)/lib -L$(LIBOQS_PREFIX)/lib
else
    CPPFLAGS += -D_FORTIFY_SOURCE=2
    LDFLAGS  += -L/usr/local/lib
endif

LDLIBS += -loqs -lssl -lcrypto

SRC_DIR = src
TEST_DIR = tests

SOURCES = $(SRC_DIR)/main.c $(SRC_DIR)/crypto_utils.c
OBJECTS = $(SOURCES:.c=.o)
EXECUTABLE = qsafe

TEST_SOURCES = $(TEST_DIR)/test_crypto_utils.c $(SRC_DIR)/crypto_utils.c
TEST_OBJECTS = $(TEST_SOURCES:.c=.o)
TEST_EXECUTABLE = $(TEST_DIR)/test_crypto

all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS) $(LDLIBS)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

test: $(EXECUTABLE) $(TEST_EXECUTABLE)
	$(TEST_DIR)/test_crypto
	$(TEST_DIR)/test.sh

$(TEST_EXECUTABLE): $(TEST_OBJECTS)
	$(CC) $(TEST_OBJECTS) -o $@ $(LDFLAGS) $(LDLIBS)

install: $(EXECUTABLE)
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(EXECUTABLE) $(DESTDIR)$(BINDIR)/$(EXECUTABLE)

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(EXECUTABLE)

clean:
	rm -f $(OBJECTS) $(EXECUTABLE) $(TEST_OBJECTS) $(TEST_EXECUTABLE)

.PHONY: all test install uninstall clean
