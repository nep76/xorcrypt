CC      = gcc
CFLAGS  = -O3 -s -mavx2 -fopt-info-vec-optimized -Wall -Wextra -Werror
LDFLAGS = -lbcrypt

SRCS = $(wildcard *.c)
OBJS = $(SRCS:.c=.o)

TARGET  = xorcrypt

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(OBJS)

distclean: clean
	rm -f $(TARGET) $(TARGET).exe
