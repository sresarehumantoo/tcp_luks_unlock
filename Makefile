CC      ?= gcc
CFLAGS  ?= -O2 -g
CFLAGS  += -std=c11 -D_GNU_SOURCE -Wall -Wextra -Wshadow -fno-strict-aliasing
CFLAGS  += -Iinclude -Ithird_party/inih
LDFLAGS ?=
LIBS    := -lsodium -lpthread
SODIUM  := -lsodium

BUILD   := build

COMMON_OBJ := \
    $(BUILD)/src/common/log.o \
    $(BUILD)/src/common/net.o \
    $(BUILD)/src/common/config.o \
    $(BUILD)/src/common/keyfile.o \
    $(BUILD)/src/common/proto.o \
    $(BUILD)/third_party/inih/ini.o

SERVER_OBJ := \
    $(BUILD)/src/server/main.o \
    $(BUILD)/src/server/handler.o \
    $(BUILD)/src/server/keystore.o \
    $(COMMON_OBJ)

CLIENT_OBJ := \
    $(BUILD)/src/client/main.o \
    $(COMMON_OBJ)

KEYGEN_OBJ := \
    $(BUILD)/tools/luks-unlock-keygen.o \
    $(BUILD)/src/common/log.o \
    $(BUILD)/src/common/keyfile.o

ENROLL_OBJ := \
    $(BUILD)/tools/luks-unlock-enroll.o \
    $(BUILD)/src/common/log.o \
    $(BUILD)/src/common/keyfile.o

BINS := \
    $(BUILD)/luks-unlock-server \
    $(BUILD)/luks-unlock-client \
    $(BUILD)/luks-unlock-keygen \
    $(BUILD)/luks-unlock-enroll

.PHONY: all clean
all: $(BINS)

$(BUILD)/luks-unlock-server: $(SERVER_OBJ)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)

$(BUILD)/luks-unlock-client: $(CLIENT_OBJ)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)

$(BUILD)/luks-unlock-keygen: $(KEYGEN_OBJ)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(SODIUM)

$(BUILD)/luks-unlock-enroll: $(ENROLL_OBJ)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(SODIUM)

# Vendored inih: silence its warnings under our strict flags.
$(BUILD)/third_party/inih/ini.o: third_party/inih/ini.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -w -c -o $@ $<

$(BUILD)/%.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf $(BUILD)
