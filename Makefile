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
	rm -f $(OBJS) MAKETEST.$(TARGET).*

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

	@cp LICENSE MAKETEST.$(TARGET).XOR
	@echo -n "Testing no-password 'xor'     : "
	@./$(TARGET) -f MAKETEST.$(TARGET).XOR
	@./$(TARGET) -f MAKETEST.$(TARGET).XOR.xnc
	@diff LICENSE MAKETEST.$(TARGET).XOR > /dev/null
	@echo "ok"

	@cp LICENSE MAKETEST.$(TARGET).PASSWD_XOR
	@echo -n "Testing password 'xor'        : "
	@./$(TARGET) -f -p password MAKETEST.$(TARGET).PASSWD_XOR
	@./$(TARGET) -f -p password MAKETEST.$(TARGET).PASSWD_XOR.xnc
	@diff LICENSE MAKETEST.$(TARGET).PASSWD_XOR > /dev/null
	@echo "ok"

	@cp LICENSE MAKETEST.$(TARGET).SEED_XOR
	@echo -n "Testing no-password 'seed-xor': "
	@./$(TARGET) -fn -a seed-xor MAKETEST.$(TARGET).SEED_XOR
	@./$(TARGET) -fn -a seed-xor MAKETEST.$(TARGET).SEED_XOR.xnc
	@diff LICENSE MAKETEST.$(TARGET).SEED_XOR > /dev/null
	@echo "ok"

	@cp LICENSE MAKETEST.$(TARGET).PASSWD_SEED_XOR
	@echo -n "Testing password 'seed-xor'   : "
	@./$(TARGET) -fn -a seed-xor -p password MAKETEST.$(TARGET).PASSWD_SEED_XOR
	@./$(TARGET) -fn -a seed-xor -p password MAKETEST.$(TARGET).PASSWD_SEED_XOR.xnc
	@diff LICENSE MAKETEST.$(TARGET).PASSWD_SEED_XOR > /dev/null
	@echo "ok"

disttest:
	@$(MAKE) --no-print-directory test
	@$(MAKE) --no-print-directory WITH_AVX2=yes test
	