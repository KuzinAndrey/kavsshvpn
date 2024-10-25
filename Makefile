###############################################
#
#  kavsshvpn - SSH based tun reverse VPN
#
#  Author: kuzinandrey@yandex.ru
#  URL: https://www.github.com/KuzinAndrey/kavsshvpn
#
###############################################

PROJ = kavsshvpn
CC = gcc
SOURCES = $(wildcard *.c)
OBJS = $(patsubst %.c,%.o,$(SOURCES))
LIBS =
BUILD =
CFLAGS = -Wall -pedantic

ifdef DEBUG
  CFLAGS += -ggdb
else
  CFLAGS += -DPRODUCTION=1
  BUILD = -s
endif

LIBS += $(shell pkg-config libssh2 --libs)
CFLAGS += $(shell pkg-config libssh2 --cflags)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

$(PROJ): $(OBJS)
	$(CC) $(BUILD) $(OBJS) $(PROD) -o $@ $(LIBS)

clean:
	rm -f $(PROJ) *.o

all: $(PROJ)
