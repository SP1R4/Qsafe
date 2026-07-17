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

SOURCES = $(SRC_DIR)/main.c $(SRC_DIR)/crypto_utils.c $(SRC_DIR)/age.c $(SRC_DIR)/keychain.c $(SRC_DIR)/sss.c $(SRC_DIR)/vault.c $(SRC_DIR)/ratchet.c $(SRC_DIR)/pqxdh.c $(SRC_DIR)/merkle.c $(SRC_DIR)/translog.c $(SRC_DIR)/group.c
OBJECTS = $(SOURCES:.c=.o)
EXECUTABLE = qsafe$(EXEEXT)

TEST_SOURCES = $(TEST_DIR)/test_crypto_utils.c $(SRC_DIR)/crypto_utils.c $(SRC_DIR)/vault.c
TEST_OBJECTS = $(TEST_SOURCES:.c=.o)
TEST_EXECUTABLE = $(TEST_DIR)/test_crypto$(EXEEXT)

# Double Ratchet module tests: behavioural conversation + key-schedule KAT.
RATCHET_TEST_SOURCES = $(TEST_DIR)/test_ratchet.c $(SRC_DIR)/ratchet.c $(SRC_DIR)/crypto_utils.c
RATCHET_TEST_EXECUTABLE = $(TEST_DIR)/test_ratchet$(EXEEXT)
RATCHET_KAT_SOURCES = $(TEST_DIR)/test_ratchet_kat.c $(SRC_DIR)/crypto_utils.c
RATCHET_KAT_EXECUTABLE = $(TEST_DIR)/test_ratchet_kat$(EXEEXT)
PQXDH_TEST_SOURCES = $(TEST_DIR)/test_pqxdh.c $(SRC_DIR)/pqxdh.c $(SRC_DIR)/ratchet.c $(SRC_DIR)/crypto_utils.c
PQXDH_TEST_EXECUTABLE = $(TEST_DIR)/test_pqxdh$(EXEEXT)
PQRATCHET_TEST_SOURCES = $(TEST_DIR)/test_pqratchet.c $(SRC_DIR)/ratchet.c $(SRC_DIR)/crypto_utils.c
PQRATCHET_TEST_EXECUTABLE = $(TEST_DIR)/test_pqratchet$(EXEEXT)
SOAK_TEST_SOURCES = $(TEST_DIR)/test_ratchet_soak.c $(SRC_DIR)/ratchet.c $(SRC_DIR)/crypto_utils.c
SOAK_TEST_EXECUTABLE = $(TEST_DIR)/test_ratchet_soak$(EXEEXT)
HE_TEST_SOURCES = $(TEST_DIR)/test_ratchet_he.c $(SRC_DIR)/ratchet.c $(SRC_DIR)/crypto_utils.c
HE_TEST_EXECUTABLE = $(TEST_DIR)/test_ratchet_he$(EXEEXT)
MERKLE_TEST_SOURCES = $(TEST_DIR)/test_merkle.c $(SRC_DIR)/merkle.c
MERKLE_TEST_EXECUTABLE = $(TEST_DIR)/test_merkle$(EXEEXT)
TRANSLOG_TEST_SOURCES = $(TEST_DIR)/test_translog.c $(SRC_DIR)/translog.c $(SRC_DIR)/merkle.c $(SRC_DIR)/crypto_utils.c
TRANSLOG_TEST_EXECUTABLE = $(TEST_DIR)/test_translog$(EXEEXT)
GROUP_TEST_SOURCES = $(TEST_DIR)/test_group.c $(SRC_DIR)/group.c $(SRC_DIR)/crypto_utils.c
GROUP_TEST_EXECUTABLE = $(TEST_DIR)/test_group$(EXEEXT)

# age plugin: post-quantum hybrid recipients for the age ecosystem.
PLUGIN = age-plugin-qsafe$(EXEEXT)
PLUGIN_OBJECTS = $(SRC_DIR)/age_plugin.o $(SRC_DIR)/crypto_utils.o

all: $(EXECUTABLE) $(PLUGIN)

plugin: $(PLUGIN)

$(PLUGIN): $(PLUGIN_OBJECTS)
	$(CC) $(EXTRA_CFLAGS) $(PLUGIN_OBJECTS) -o $@ $(LDFLAGS) $(EXTRA_LDFLAGS) $(LDLIBS)

# EXTRA_CFLAGS / EXTRA_LDFLAGS are appended to every compile and link, so CI can
# layer in sanitizers without clobbering the baseline flags, e.g.:
#   make EXTRA_CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g" \
#        EXTRA_LDFLAGS="-fsanitize=address,undefined"
$(EXECUTABLE): $(OBJECTS)
	$(CC) $(EXTRA_CFLAGS) $(OBJECTS) -o $@ $(LDFLAGS) $(EXTRA_LDFLAGS) $(LDLIBS)

HEADERS = $(wildcard include/*.h)

%.o: %.c $(HEADERS)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(EXTRA_CFLAGS) -c $< -o $@

test: $(EXECUTABLE) $(TEST_EXECUTABLE) test-ratchet
	./$(TEST_EXECUTABLE)
	$(TEST_DIR)/test.sh

$(TEST_EXECUTABLE): $(TEST_OBJECTS)
	$(CC) $(EXTRA_CFLAGS) $(TEST_OBJECTS) -o $@ $(LDFLAGS) $(EXTRA_LDFLAGS) $(LDLIBS)

# Double Ratchet: build both harnesses from source (no shared .o with the main
# binary so sanitizer flags can be layered independently) and run them.
test-ratchet: $(RATCHET_TEST_EXECUTABLE) $(RATCHET_KAT_EXECUTABLE) $(PQXDH_TEST_EXECUTABLE) $(PQRATCHET_TEST_EXECUTABLE) $(SOAK_TEST_EXECUTABLE) $(HE_TEST_EXECUTABLE) $(MERKLE_TEST_EXECUTABLE) $(TRANSLOG_TEST_EXECUTABLE) $(GROUP_TEST_EXECUTABLE)
	./$(RATCHET_KAT_EXECUTABLE)
	./$(RATCHET_TEST_EXECUTABLE)
	./$(PQXDH_TEST_EXECUTABLE)
	./$(PQRATCHET_TEST_EXECUTABLE)
	./$(SOAK_TEST_EXECUTABLE)
	./$(HE_TEST_EXECUTABLE)
	./$(MERKLE_TEST_EXECUTABLE)
	./$(TRANSLOG_TEST_EXECUTABLE)
	./$(GROUP_TEST_EXECUTABLE)

$(PQRATCHET_TEST_EXECUTABLE): $(PQRATCHET_TEST_SOURCES) $(HEADERS)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(EXTRA_CFLAGS) $(PQRATCHET_TEST_SOURCES) -o $@ \
		$(LDFLAGS) $(EXTRA_LDFLAGS) $(LDLIBS)

$(HE_TEST_EXECUTABLE): $(HE_TEST_SOURCES) $(HEADERS)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(EXTRA_CFLAGS) $(HE_TEST_SOURCES) -o $@ \
		$(LDFLAGS) $(EXTRA_LDFLAGS) $(LDLIBS)

$(MERKLE_TEST_EXECUTABLE): $(MERKLE_TEST_SOURCES) $(HEADERS)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(EXTRA_CFLAGS) $(MERKLE_TEST_SOURCES) -o $@ \
		$(LDFLAGS) $(EXTRA_LDFLAGS) $(LDLIBS)

$(TRANSLOG_TEST_EXECUTABLE): $(TRANSLOG_TEST_SOURCES) $(HEADERS)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(EXTRA_CFLAGS) $(TRANSLOG_TEST_SOURCES) -o $@ \
		$(LDFLAGS) $(EXTRA_LDFLAGS) $(LDLIBS)

$(GROUP_TEST_EXECUTABLE): $(GROUP_TEST_SOURCES) $(HEADERS)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(EXTRA_CFLAGS) $(GROUP_TEST_SOURCES) -o $@ \
		$(LDFLAGS) $(EXTRA_LDFLAGS) $(LDLIBS)

$(SOAK_TEST_EXECUTABLE): $(SOAK_TEST_SOURCES) $(HEADERS)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(EXTRA_CFLAGS) $(SOAK_TEST_SOURCES) -o $@ \
		$(LDFLAGS) $(EXTRA_LDFLAGS) $(LDLIBS)

$(RATCHET_TEST_EXECUTABLE): $(RATCHET_TEST_SOURCES) $(HEADERS)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(EXTRA_CFLAGS) $(RATCHET_TEST_SOURCES) -o $@ \
		$(LDFLAGS) $(EXTRA_LDFLAGS) $(LDLIBS)

$(RATCHET_KAT_EXECUTABLE): $(RATCHET_KAT_SOURCES) $(HEADERS)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(EXTRA_CFLAGS) $(RATCHET_KAT_SOURCES) -o $@ \
		$(LDFLAGS) $(EXTRA_LDFLAGS) $(LDLIBS)

$(PQXDH_TEST_EXECUTABLE): $(PQXDH_TEST_SOURCES) $(HEADERS)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(EXTRA_CFLAGS) $(PQXDH_TEST_SOURCES) -o $@ \
		$(LDFLAGS) $(EXTRA_LDFLAGS) $(LDLIBS)

# --- Shared library (libqsafe) ------------------------------------------------
# A stable C API around the engine; used by the language bindings (python/).
lib: $(LIBRARY)

$(LIBRARY): $(SRC_DIR)/crypto_utils.c $(SRC_DIR)/libqsafe.c $(SRC_DIR)/vault.c $(SRC_DIR)/ratchet.c $(SRC_DIR)/pqxdh.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(EXTRA_CFLAGS) -fPIC -shared $^ -o $@ \
		$(LDFLAGS) $(EXTRA_LDFLAGS) $(LDLIBS)

# --- Constant-time check (Linux + valgrind) -----------------------------------
# ctgrind-style harness: secrets are marked uninitialized and valgrind flags
# any branch/index that depends on them. Run: make ct && valgrind
# --error-exitcode=1 tests/ct_check
CT_EXECUTABLE = $(TEST_DIR)/ct_check$(EXEEXT)

ct: $(CT_EXECUTABLE)

$(CT_EXECUTABLE): $(TEST_DIR)/ct_check.c $(SRC_DIR)/crypto_utils.o
	$(CC) $(CPPFLAGS) $(CFLAGS) $(EXTRA_CFLAGS) $(TEST_DIR)/ct_check.c $(SRC_DIR)/crypto_utils.o \
		-o $@ $(LDFLAGS) $(EXTRA_LDFLAGS) $(LDLIBS)

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

# vault (hidden volumes) has its own harness: see tests/fuzz_vault.c for why
# it fuzzes raw container bytes only, not the (offset, capacity) arithmetic.
FUZZ_VAULT_EXECUTABLE = $(TEST_DIR)/fuzz_vault

fuzz-vault: $(FUZZ_VAULT_EXECUTABLE)

$(FUZZ_VAULT_EXECUTABLE): $(TEST_DIR)/fuzz_vault.c $(SRC_DIR)/crypto_utils.c $(SRC_DIR)/vault.c
	$(FUZZ_CC) $(CPPFLAGS) -g -O1 -fsanitize=$(FUZZ_SANITIZE) \
		$(TEST_DIR)/fuzz_vault.c $(SRC_DIR)/crypto_utils.c $(SRC_DIR)/vault.c \
		-o $@ $(LDFLAGS) $(LDLIBS)

# vault v2 directory parser: attacker-influenced bytes once an anchor decrypts.
FUZZ_VAULT_DIR_EXECUTABLE = $(TEST_DIR)/fuzz_vault_dir

fuzz-vault-dir: $(FUZZ_VAULT_DIR_EXECUTABLE)

$(FUZZ_VAULT_DIR_EXECUTABLE): $(TEST_DIR)/fuzz_vault_dir.c $(SRC_DIR)/crypto_utils.c $(SRC_DIR)/vault.c
	$(FUZZ_CC) $(CPPFLAGS) -g -O1 -fsanitize=$(FUZZ_SANITIZE) \
		$(TEST_DIR)/fuzz_vault_dir.c $(SRC_DIR)/crypto_utils.c $(SRC_DIR)/vault.c \
		-o $@ $(LDFLAGS) $(LDLIBS)

MANDIR ?= $(PREFIX)/share/man/man1
BASHCOMPDIR ?= $(PREFIX)/etc/bash_completion.d
ZSHCOMPDIR ?= $(PREFIX)/share/zsh/site-functions

install: $(EXECUTABLE) $(PLUGIN)
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(EXECUTABLE) $(DESTDIR)$(BINDIR)/$(EXECUTABLE)
	install -m 0755 $(PLUGIN) $(DESTDIR)$(BINDIR)/$(PLUGIN)
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
	rm -f $(OBJECTS) $(EXECUTABLE) $(TEST_OBJECTS) $(TEST_EXECUTABLE) $(FUZZ_EXECUTABLE) $(LIBRARY) $(PLUGIN) $(SRC_DIR)/age_plugin.o $(CT_EXECUTABLE)

.PHONY: all test lib plugin ct fuzz install install-completions uninstall clean
