CC = gcc
CFLAGS = -fstack-protector-all -no-pie -O0 -g

all: pastry_shop

pastry_shop: main.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f pastry_shop
