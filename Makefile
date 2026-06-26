CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Wformat -Wformat-security -O2 -fstack-protector-strong
CPPFLAGS += -Iinclude

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

UNAME_S := $(shell uname -s)

# --- Dependency discovery -----------------------------------------------------
# On macOS use Homebrew prefixes when available; otherwise fall back to
# /usr/local. On Linux assume system include paths plus /usr/local/lib.
EXEEXT =

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
    # macOS Keychain backing (src/keychain.c) uses the Security framework.
    LDLIBS   += -framework Security -framework CoreFoundation
else ifneq (,$(filter MINGW% MSYS% CYGWIN%,$(UNAME_S)))
    # Windows via MSYS2/MinGW-w64. openssl + liboqs from the mingw prefix are on
    # the default search path; set LIBOQS_PREFIX/OPENSSL_PREFIX to override.
    EXEEXT = .exe
    WINDOWS = 1
    ifdef OPENSSL_PREFIX
        CPPFLAGS += -I$(OPENSSL_PREFIX)/include
        LDFLAGS  += -L$(OPENSSL_PREFIX)/lib
    endif
    ifdef LIBOQS_PREFIX
        CPPFLAGS += -I$(LIBOQS_PREFIX)/include
        LDFLAGS  += -L$(LIBOQS_PREFIX)/lib
    endif
else
    CPPFLAGS += -D_FORTIFY_SOURCE=2
    LDFLAGS  += -L/usr/local/lib
endif

LDLIBS += -loqs -lssl -lcrypto
# OpenSSL on Windows pulls in these system libraries (needed for static links).
ifdef WINDOWS
    LDLIBS += -lws2_32 -lcrypt32 -lbcrypt
endif

# Shared-library suffix per platform.
ifeq ($(UNAME_S),Darwin)
    LIBEXT = .dylib
else ifdef WINDOWS
    LIBEXT = .dll
else
    LIBEXT = .so
endif
LIBRARY = libqsafe$(LIBEXT)

SRC_DIR = src
TEST_DIR = tests

SOURCES = $(SRC_DIR)/main.c $(SRC_DIR)/crypto_utils.c $(SRC_DIR)/age.c $(SRC_DIR)/keychain.c
OBJECTS = $(SOURCES:.c=.o)
EXECUTABLE = qsafe$(EXEEXT)

TEST_SOURCES = $(TEST_DIR)/test_crypto_utils.c $(SRC_DIR)/crypto_utils.c
TEST_OBJECTS = $(TEST_SOURCES:.c=.o)
TEST_EXECUTABLE = $(TEST_DIR)/test_crypto$(EXEEXT)

all: $(EXECUTABLE)

# EXTRA_CFLAGS / EXTRA_LDFLAGS are appended to every compile and link, so CI can
# layer in sanitizers without clobbering the baseline flags, e.g.:
#   make EXTRA_CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g" \
#        EXTRA_LDFLAGS="-fsanitize=address,undefined"
$(EXECUTABLE): $(OBJECTS)
	$(CC) $(EXTRA_CFLAGS) $(OBJECTS) -o $@ $(LDFLAGS) $(EXTRA_LDFLAGS) $(LDLIBS)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(EXTRA_CFLAGS) -c $< -o $@

test: $(EXECUTABLE) $(TEST_EXECUTABLE)
	./$(TEST_EXECUTABLE)
	$(TEST_DIR)/test.sh

$(TEST_EXECUTABLE): $(TEST_OBJECTS)
	$(CC) $(EXTRA_CFLAGS) $(TEST_OBJECTS) -o $@ $(LDFLAGS) $(EXTRA_LDFLAGS) $(LDLIBS)

# --- Shared library (libqsafe) ------------------------------------------------
# A stable C API around the engine; used by the language bindings (python/).
lib: $(LIBRARY)

$(LIBRARY): $(SRC_DIR)/crypto_utils.c $(SRC_DIR)/libqsafe.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(EXTRA_CFLAGS) -fPIC -shared $^ -o $@ \
		$(LDFLAGS) $(EXTRA_LDFLAGS) $(LDLIBS)

# --- Fuzzing (requires clang + libFuzzer) -------------------------------------
# Builds an instrumented harness over the untrusted-input parsers. Run with:
#   tests/fuzz_decrypt -max_len=8192 corpus/
FUZZ_CC ?= clang
FUZZ_SANITIZE ?= fuzzer,address,undefined
FUZZ_EXECUTABLE = $(TEST_DIR)/fuzz_decrypt

fuzz: $(FUZZ_EXECUTABLE)

$(FUZZ_EXECUTABLE): $(TEST_DIR)/fuzz_decrypt.c $(SRC_DIR)/crypto_utils.c
	$(FUZZ_CC) $(CPPFLAGS) -g -O1 -fsanitize=$(FUZZ_SANITIZE) \
		$(TEST_DIR)/fuzz_decrypt.c $(SRC_DIR)/crypto_utils.c \
		-o $@ $(LDFLAGS) $(LDLIBS)

MANDIR ?= $(PREFIX)/share/man/man1
BASHCOMPDIR ?= $(PREFIX)/etc/bash_completion.d
ZSHCOMPDIR ?= $(PREFIX)/share/zsh/site-functions

install: $(EXECUTABLE)
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(EXECUTABLE) $(DESTDIR)$(BINDIR)/$(EXECUTABLE)
	install -d $(DESTDIR)$(MANDIR)
	install -m 0644 docs/qsafe.1 $(DESTDIR)$(MANDIR)/qsafe.1

# Optional: install shell completions into the conventional directories.
install-completions:
	install -d $(DESTDIR)$(BASHCOMPDIR)
	install -m 0644 completions/qsafe.bash $(DESTDIR)$(BASHCOMPDIR)/qsafe
	install -d $(DESTDIR)$(ZSHCOMPDIR)
	install -m 0644 completions/_qsafe $(DESTDIR)$(ZSHCOMPDIR)/_qsafe

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(EXECUTABLE)
	rm -f $(DESTDIR)$(MANDIR)/qsafe.1
	rm -f $(DESTDIR)$(BASHCOMPDIR)/qsafe
	rm -f $(DESTDIR)$(ZSHCOMPDIR)/_qsafe

clean:
	rm -f $(OBJECTS) $(EXECUTABLE) $(TEST_OBJECTS) $(TEST_EXECUTABLE) $(FUZZ_EXECUTABLE) $(LIBRARY)

.PHONY: all test lib fuzz install install-completions uninstall clean
