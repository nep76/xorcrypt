CC      ?= gcc
CFLAGS  ?= -O3 -D_FILE_OFFSET_BITS=64 -ffunction-sections -fdata-sections -Wall -Wextra -Werror
LDFLAGS ?= -s -Wl,--gc-sections
LIBS    =

SUFFIX =

ifdef WITH_OPTINFO
	CFLAGS += -fopt-info
endif

ifdef WITH_AVX2
	CFLAGS += -mavx2 -mbmi -mbmi2 -mfma
	SUFFIX = -avx2
endif

ifdef WITH_NATIVE
	CFLAGS += -march=native
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
	rm -f $(OBJS) MAKETEST.*

binclean:
	rm -f $(TARGET) $(TARGET).exe

allclean:
	$(MAKE) clean
	$(MAKE) binclean
	$(MAKE) clean
	$(MAKE) WITH_AVX2=yes binclean

rebuild: objclean all

dist: allclean
	$(MAKE) all
	$(MAKE) clean
	$(MAKE) WITH_AVX2=yes all
	$(MAKE) clean

distclean: allclean

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
	