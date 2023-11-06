.PHONY: all

all: e2e unwind

e2e: e2e.c
	gcc $< -o $@

unwind: unwind.cpp
	g++ $< -o $@ -O2
