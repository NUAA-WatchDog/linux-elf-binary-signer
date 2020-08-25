

all: lib main.c
	gcc main.c -L. -ltest -o main
lib: test.c
	gcc test.c -fPIC -shared -o libtest.so
