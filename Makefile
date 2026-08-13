CC ?= gcc
CLANG ?= clang

BUILD_DIR := build
PROFILE ?= debug
TEST_EPOLL ?= 0

PROFILE_CFLAGS_debug := -Og -g3 -DDEBUG
PROFILE_CFLAGS_release := -O2 -DNDEBUG
PROFILE_CFLAGS_relwithdebinfo := -O2 -g -DNDEBUG

PROFILE_BPF_CFLAGS_debug := -O0 -g
PROFILE_BPF_CFLAGS_release := -O2 -g
PROFILE_BPF_CFLAGS_relwithdebinfo := -O2 -g

PROFILE_CFLAGS := $(PROFILE_CFLAGS_$(PROFILE))
PROFILE_BPF_CFLAGS := $(PROFILE_BPF_CFLAGS_$(PROFILE))

ifeq ($(strip $(PROFILE_CFLAGS)),)
$(error unknown PROFILE '$(PROFILE)'; use debug, release, or relwithdebinfo)
endif

LIB := $(BUILD_DIR)/libnetfast.so
HEADER := $(BUILD_DIR)/netfast.h
BPF_DIR := $(BUILD_DIR)/bpf
BPF_SRC := lib/xdp_redirect.bpf.c
BPF_OBJ := $(BPF_DIR)/xdp_redirect.bpf.o
PROFILE_STAMP := $(BUILD_DIR)/.build-profile

SRC_LIB := \
	lib/base.c \
	lib/hash.c \
	lib/list.c \
	lib/log.c \
	lib/queue.c \
	lib/rss.c \
	lib/frame_cache.c \
	lib/thread.c \
	lib/trie.c \
	lib/xdp.c
SRC_MAIN := \
	main/ether.c \
	main/fd_entry.c \
	main/icmp.c \
	main/if.c \
	main/init.c \
	main/ip.c \
	main/ip_frag.c \
	main/ipv6.c \
	main/ipv6_ext.c \
	main/loopback.c \
	main/req_epoll.c \
	main/netlink.c \
	main/req.c \
	main/req_async.c \
	main/req_socket.c \
	main/route_arp_ndp.c \
	main/skbuff.c \
	main/socket.c \
	main/stack.c \
	main/tcp.c \
	main/tcp_congestion.c \
	main/tcp_metrics.c \
	main/udp.c \
	main/worker.c
SRCS := $(SRC_LIB) $(SRC_MAIN)
OBJS := $(patsubst %.c,$(BUILD_DIR)/%.o,$(SRCS))

BPF_ARCH ?= $(shell uname -m | sed -e 's/x86_64/x86/' -e 's/aarch64/arm64/')

CFLAGS ?= $(PROFILE_CFLAGS) -Wall -Wextra -MMD -MP -D_GNU_SOURCE
CFLAGS += -I. -Ilib -Imain -pthread -fPIC

ifeq ($(TEST_EPOLL),1)
CFLAGS += -DTEST_EPOLL
endif

# 处理大静态数据/.bss 场景下的重定位溢出
CFLAGS += -mcmodel=large

BPF_CFLAGS ?= $(PROFILE_BPF_CFLAGS) -target bpf -D__TARGET_ARCH_$(BPF_ARCH)

BPF_MULTIARCH ?= $(shell $(CC) -print-multiarch 2>/dev/null)
ifneq ($(strip $(BPF_MULTIARCH)),)
BPF_CFLAGS += -I/usr/include/$(BPF_MULTIARCH)
endif
LDLIBS ?= -lbpf -lelf -lz -pthread -lxdp -lcjson


PREFIX ?= /usr/local
INCLUDE_DIR ?= $(PREFIX)/include
LIB_DIR ?= $(PREFIX)/lib
BPF_INSTALL_DIR ?= $(PREFIX)/lib/bpf
CONFIG_DIR ?= $(PREFIX)/etc/netfast
CONFIG_FILE ?= $(firstword $(wildcard netfast_config.json) config.example.json)

.DEFAULT_GOAL := debug

.PHONY: all build clean bpf install uninstall debug release relwithdebinfo ftp-async FORCE

all: debug

build: $(LIB) $(BPF_OBJ) $(HEADER)

bpf: $(BPF_OBJ)

$(HEADER): main/netfast.h
	@mkdir -p $(dir $@)
	cp $< $@

$(LIB): $(OBJS)
	@mkdir -p $(dir $@)
	$(CC) -shared -Wl,-soname,libnetfast.so $(OBJS) -o $@ $(LDLIBS)

$(PROFILE_STAMP): FORCE
	@mkdir -p $(dir $@)
	@{ \
		printf 'PROFILE=%s\n' '$(PROFILE)'; \
		printf 'CFLAGS=%s\n' '$(CFLAGS)'; \
		printf 'BPF_CFLAGS=%s\n' '$(BPF_CFLAGS)'; \
		printf 'LDLIBS=%s\n' '$(LDLIBS)'; \
	} > $@.tmp
	@cmp -s $@.tmp $@ || mv $@.tmp $@
	@rm -f $@.tmp

$(BUILD_DIR)/%.o: %.c $(PROFILE_STAMP)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(BPF_DIR)/xdp_redirect.bpf.o: lib/xdp_redirect.bpf.c $(PROFILE_STAMP)
	@mkdir -p $(BPF_DIR)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

clean:
	@test ! -d $(BUILD_DIR) || find $(BUILD_DIR) -type f ! -name '.fuse_hidden*' -delete
	@test ! -d $(BUILD_DIR) || find $(BUILD_DIR) -type l -delete
	@test ! -d $(BUILD_DIR) || find $(BUILD_DIR) -depth -type d -empty -delete

debug:
	$(MAKE) PROFILE=debug build

release:
	$(MAKE) PROFILE=release build

relwithdebinfo:
	$(MAKE) PROFILE=relwithdebinfo build

$(BUILD_DIR)/example/ftp_async_server: example/ftp_async.c $(LIB)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $< -L$(BUILD_DIR) -Wl,-rpath,'$$ORIGIN/..' -lnetfast -o $@

ftp-async: $(BUILD_DIR)/example/ftp_async_server

install: $(LIB) $(BPF_OBJ) $(HEADER) $(CONFIG_FILE)
	install -d $(DESTDIR)$(LIB_DIR)
	install -m 755 $(LIB) $(DESTDIR)$(LIB_DIR)/libnetfast.so
	install -d $(DESTDIR)$(INCLUDE_DIR)
	install -m 644 $(HEADER) $(DESTDIR)$(INCLUDE_DIR)/netfast.h
	install -d $(DESTDIR)$(BPF_INSTALL_DIR)
	for f in $(BPF_OBJ); do install -m 644 $$f $(DESTDIR)$(BPF_INSTALL_DIR)/ ; done
	install -d $(DESTDIR)$(CONFIG_DIR)
	install -m 644 $(CONFIG_FILE) $(DESTDIR)$(CONFIG_DIR)/netfast_config.json
	ldconfig $(DESTDIR)$(LIB_DIR) 2>/dev/null || true

uninstall:
	rm -f $(DESTDIR)$(LIB_DIR)/libnetfast.so
	rm -f $(DESTDIR)$(INCLUDE_DIR)/netfast.h
	for f in $(notdir $(BPF_OBJ)); do rm -f $(DESTDIR)$(BPF_INSTALL_DIR)/$$f; done
	rm -f $(DESTDIR)$(CONFIG_DIR)/netfast_config.json
	ldconfig $(DESTDIR)$(LIB_DIR) 2>/dev/null || true

-include $(OBJS:.o=.d)
