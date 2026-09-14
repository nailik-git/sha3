BUILD ?= build
CC ?= cc
CFLAGS := $(CFLAGS) -O3 -g

.PHONY: all

all: |$(BUILD) $(BUILD)/example

$(BUILD)/example: example.c $(BUILD)/libsha3.a sha3.h
	$(CC) -o $@ $< -L=$(BUILD) -lsha3

$(BUILD)/libsha3.a: $(BUILD)/sha3.o
	ar rsc $@ $<

$(BUILD)/sha3.o: sha3.c sha3.h
	$(CC) $(CFLAGS) -c -o $@ $< 

$(BUILD):
	mkdir -p $(BUILD)

clean:
	rm -r $(BUILD)

