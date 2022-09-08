CC = /usr/bin/gcc
CFLAGS = -Wall -g -O3 -Wextra -Wpedantic
LDLIBS = -lcrypto

SOURCES = params.c hash.c fips202.c hash_address.c randombytes.c wots.c utils.c imt.c smt.c xmss.c xmss_core.c xmss_commons.c dgmt_utils.c dgmt.c
HEADERS = params.h hash.h fips202.h hash_address.h randombytes.h wots.h utils.h imt.h smt.h xmss.h xmss_core.h xmss_commons.h dgmt_utils.h dgmt.h

SOURCES_FAST = $(subst xmss_core.c,xmss_core_fast.c,$(SOURCES))
HEADERS_FAST = $(subst xmss_core.c,xmss_core_fast.c,$(HEADERS))

TESTS = test/dgmt_main \

tests: $(TESTS)

test: $(TESTS:=.exec)

.PHONY: clean test

test/%.exec: test/%
	@$<

test/%: test/%.c $(SOURCES) $(OBJS) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $< $(LDLIBS)

clean:
	-$(RM) $(TESTS)
	-$(RM) test/vectors
	-$(RM) $(UI)
