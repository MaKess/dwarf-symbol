.PHONY: all clean test

all: dwarf-symbol

clean:
	rm -rf dwarf-symbol

test: dwarf-symbol
	./$< $<
	./$< $< 1337

dwarf-symbol: dwarf-symbol.cpp
	g++ -O2 -Wall -g -o $@ $^ -lfmt
