CC      ?= gcc
CFLAGS  ?= -O3 -march=x86-64 -mtune=generic -Wall -Wextra -Werror
LDFLAGS ?= -s
LIBS    =

SUFFIX =

ifdef WITH_AVX2
	CFLAGS += -mavx2 -mbmi -mbmi2 -mfma -fopt-info-vec-optimized
	SUFFIX = -avx2
endif

ifeq ($(OS), Windows_NT)
	LIBS += -lbcrypt
else
	LIBS += -lcrypto
endif

SRCS = $(wildcard *.c)
OBJS = $(SRCS:.c=.o)

TARGET  = xorcrypt$(SUFFIX)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o $(TARGET) $(LIBS)

clean:
	rm -f $(OBJS)

allclean: clean
	rm -f $(TARGET) $(TARGET).exe

rebuild: clean all

dist:
	$(MAKE) clean
	$(MAKE) all
	$(MAKE) clean
	$(MAKE) WITH_AVX2=yes all
	$(MAKE) clean

distclean:
	$(MAKE) allclean
	$(MAKE) WITH_AVX2=yes allclean

test:
	@cp LICENSE DELETEME.TXT
	@echo "--- Testing no-password XOR ---"
	./xorcrypt DELETEME.TXT || true
	./xorcrypt DELETEME.TXT.

