all: udp-client-evil
CONTIKI=../../..

CFLAGS += -DPROJECT_CONF_H=\"project-conf.h\"

APPS+=powertrace
CFLAGS+= -DCONTIKIMAC_CONF_COMPOWER=1 -DWITH_COMPOWER=1 -DQUEUEBUF_CONF_NUM=4

CFLAGS+=-DSERVER_REPLY=1

ifdef PERIOD
CFLAGS+=-DPERIOD=$(PERIOD)
endif

ifeq ($(MAKE_WITH_NON_STORING),1)
CFLAGS += -DWITH_NON_STORING=1
endif

CONTIKI_WITH_IPV6 = 1
include $(CONTIKI)/Makefile.include
