CC ?= gcc
CFLAGS ?= -O3 -march=native -Wall -Wextra -pthread
TARGET = vguard_fast_dpi
SRCS = vguard_fast_dpi.c

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS)

benchmark: $(TARGET)
	./$(TARGET) --benchmark

clean:
	rm -f $(TARGET) *.o

.PHONY: all clean benchmark
