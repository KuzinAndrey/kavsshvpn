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
CFLAGS = -Wall -Werror -Wextra -pedantic -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2

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

install: $(PROJ)
	cp -v $(PROJ) /bin/

clean:
	rm -f $(PROJ) *.o

all: $(PROJ)
