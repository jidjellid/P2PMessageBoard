compile:
	cd rfc6234 || git clone https://github.com/massar/rfc6234
	gcc -Wall -o build/server src/server.c

run:
	./build/server $(arg1) $(arg2)

debug:
	valgrind --leak-check=yes ./build/server $(arg1) $(arg2)