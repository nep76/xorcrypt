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

TARGET = xorcrypt$(SUFFIX)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o $(TARGET) $(LIBS)

clean:
	rm -f $(OBJS) MAKETEST MAKETEST.xnc

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
	@echo "--- Testing $(TARGET) ---"
	@cp LICENSE MAKETEST

	@echo -n "Testing no-password 'xor'     : "
	@./$(TARGET) -f MAKETEST
	@./$(TARGET) -f MAKETEST.xnc
	@diff LICENSE MAKETEST
	@echo "ok"

	@echo -n "Testing password 'xor'        : "
	@./$(TARGET) -f -p password MAKETEST
	@./$(TARGET) -f -p password MAKETEST.xnc
	@diff LICENSE MAKETEST
	@echo "ok"

	@echo -n "Testing no-password 'seed-xor': "
	@./$(TARGET) -fn -a seed-xor MAKETEST
	@./$(TARGET) -fn -a seed-xor MAKETEST.xnc
	@diff LICENSE MAKETEST
	@echo "ok"

	@echo -n "Testing password 'seed-xor'   : "
	@./$(TARGET) -fn -a seed-xor -p password MAKETEST
	@./$(TARGET) -fn -a seed-xor -p password MAKETEST.xnc
	@diff LICENSE MAKETEST
	@echo "ok"

	@rm MAKETEST MAKETEST.xnc

disttest:
	@$(MAKE) --no-print-directory test
	@$(MAKE) --no-print-directory WITH_AVX2=yes test
	