# Adjust these two for your tree
QEMU_SRC   ?= $(HOME)/Downloads/qemu
QEMU_BUILD ?= $(HOME)/Downloads/qemu/build

CC      := cc
CFLAGS  := -fPIC -O2 -g -pthread \
           $(shell pkg-config --cflags glib-2.0) \
           -I$(QEMU_SRC)/include/qemu -I$(QEMU_BUILD)/include -I$(QEMU_BUILD) -I$(QEMU_SRC)/plugins/scallopshell/include
LDFLAGS := -shared -pthread $(shell pkg-config --libs glib-2.0)

SRCS := gate.c control.c memregs.c logging.c plugin.c
OBJS := $(SRCS:.c=.o)

all: branchlog.so

branchlog.so: $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)

%.o: %.c include/branchlog.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) branchlog.so
