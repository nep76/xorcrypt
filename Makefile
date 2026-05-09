CC      = gcc
CFLAGS  = -O3 -s -mavx2 -fopt-info-vec-optimized -Wall -Wextra -Werror
LDFLAGS = 
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
	$(CC) $(OBJS) -o $(TARGET) $(LIBS)

clean:
	rm -f $(OBJS)

distclean: clean
	rm -f $(TARGET) $(TARGET).exe
