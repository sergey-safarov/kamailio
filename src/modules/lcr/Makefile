#
# Least Cost Routing Module
#
#
# WARNING: do not run this directly, it should be run by the main Makefile

include ../../Makefile.defs
auto_gen=
NAME=lcr.so

ifeq ($(CROSS_COMPILE),)
PCRE_BUILDER = $(shell command -v pcre2-config)
endif

ifeq ($(PCRE_BUILDER),)
	PCREDEFS=-I$(LOCALBASE)/include
	PCRELIBS=-L$(LOCALBASE)/lib -lpcre2-8
else
	PCREDEFS = $(shell $(PCRE_BUILDER) --cflags)
	PCRELIBS = $(shell $(PCRE_BUILDER) --libs8)
endif

DEFS+=$(PCREDEFS)
LIBS+=$(PCRELIBS)

include ../../Makefile.modules
