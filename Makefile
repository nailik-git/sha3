BUILD := build

.PHONY: all

all: |$(BUILD) $(BUILD)/example

$(BUILD)/example: example.c $(BUILD)/libsha3.a sha3.h
	clang -o $@ $< -L=$(BUILD) -lsha3

$(BUILD)/libsha3.a: $(BUILD)/sha3.o
	ar rsc $@ $<

$(BUILD)/sha3.o: sha3.c sha3.h
	clang -O3 -c -o $@ $< 

$(BUILD):
	mkdir -p $(BUILD)

clean:
	rm -r $(BUILD)

