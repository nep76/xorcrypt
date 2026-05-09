CC      = gcc
CFLAGS  = -O3 -mavx2 -fopt-info-vec-optimized -Wall -Wextra -Werror
LDFLAGS = -s
LIBS    =

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
