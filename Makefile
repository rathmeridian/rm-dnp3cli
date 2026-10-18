CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=c11
TARGET   = dnp3cli

all: $(TARGET)

$(TARGET): dnp3cli.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

.PHONY: all clean
