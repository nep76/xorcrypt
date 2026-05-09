CC      = gcc
CFLAGS  ?= -O3 -march=x86-64 -mtune=generic -Wall -Wextra -Werror
LDFLAGS ?= -s
LIBS    =

ifdef WITH_AVX2
	CFLAGS += -mavx2 -mbmi -mbmi2 -mfma -fopt-info-vec-optimized
endif

ifeq ($(OS), Windows_NT)
	LIBS += -lbcrypt
else
	LIBS += -lcrypto
endif

SRCS = $(wildcard *.c)
OBJS = $(SRCS:.c=.o)

TARGET  = xorcrypt

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS) $(LIBS)

clean:
	rm -f $(OBJS)

distclean: clean
	rm -f $(TARGET) $(TARGET).exe

rebuild: clean all
