CC      = gcc
CFLAGS  = -std=c99 -O3 -s -mavx2 -fopt-info-vec-optimized -Wall
LDFLAGS = -lbcrypt

OBJS = main.o

TARGET  = xorcrypt

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(OBJS) $(TARGET)
