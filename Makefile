all:
	gcc src/main.c -O2 -o game_of_life -lncurses
run:
	$(all)
	./game_of_life
clean:
	rm game_of_life
.PHONY: format
format:
	clang-format -style='{IndentWidth: 4, BasedOnStyle: Google}' -i src/*.c

.PHONY: all clean
