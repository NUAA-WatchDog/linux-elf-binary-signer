
all: lib so_test.c
	cc so_test.c -L. -ltest -o so-test
lib: test.c
	cc test.c -fPIC -shared -o libtest.so
clean: 
	$(RM) so-test
	$(RM) *.so
	$(RM) *.old
