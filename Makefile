CC      = gcc
CFLAGS  = -std=c99 -O3 -s -mavx2 -fopt-info-vec-optimized -Wall 
LDFLAGS = -lbcrypt

SRCS = $(wildcard *.c)
OBJS = $(SRCS:.c=.o)

TARGET  = xorcrypt

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(OBJS) $(TARGET)
