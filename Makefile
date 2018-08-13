all: sha256 h256


h256: sha256.c
	gcc -O2 -Wall -Wextra -std=c99 -UNDEBUG -DTEST_HMAC_SHA256 -o $@ $^

sha256: sha256.c
	gcc -O2 -Wall -Wextra -std=c99 -UNDEBUG -DTEST_SHA256 -o $@ $^

clean:
	rm -f sha256 h256
