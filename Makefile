CC      ?= gcc
CFLAGS  ?= -O3 -Wall -Wextra -Werror -march=x86-64 -mtune=generic
LDFLAGS ?= -s
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

objclean:
	rm -f $(OBJS) MAKETEST.$(TARGET).*

binclean:
	rm -f $(TARGET) $(TARGET).exe

clean: 
	$(MAKE) objclean
	$(MAKE) WITH_AVX2=yes objclean

allclean:
	$(MAKE) objclean
	$(MAKE) binclean
	$(MAKE) WITH_AVX2=yes objclean
	$(MAKE) WITH_AVX2=ues binclean

rebuild: objclean all

dist:
	$(MAKE) clean
	$(MAKE) all
	$(MAKE) objclean
	$(MAKE) WITH_AVX2=yes all
	$(MAKE) WITH_AVX2=yes objclean

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
	