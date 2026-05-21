CC = gcc
CFLAGS = -Iinclude -std=c11 -Wall -Wextra -Wformat -Wformat-security -O2 \
         -fstack-protector-strong -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2
LDFLAGS = -L/usr/local/lib -loqs -lssl -lcrypto

SRC_DIR = src
INCLUDE_DIR = include
TEST_DIR = tests

SOURCES = $(SRC_DIR)/main.c $(SRC_DIR)/crypto_utils.c
OBJECTS = $(SOURCES:.c=.o)
EXECUTABLE = crypto-v2

TEST_SOURCES = $(TEST_DIR)/test_crypto_utils.c $(SRC_DIR)/crypto_utils.c
TEST_OBJECTS = $(TEST_SOURCES:.c=.o)
TEST_EXECUTABLE = $(TEST_DIR)/test_crypto

all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

$(SRC_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

test: $(EXECUTABLE) $(TEST_EXECUTABLE)
	$(TEST_DIR)/test_crypto
	$(TEST_DIR)/test.sh

$(TEST_EXECUTABLE): $(TEST_OBJECTS)
	$(CC) $(TEST_OBJECTS) -o $@ $(LDFLAGS)

$(TEST_DIR)/%.o: $(TEST_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(EXECUTABLE) $(TEST_OBJECTS) $(TEST_EXECUTABLE)

.PHONY: all test clean
