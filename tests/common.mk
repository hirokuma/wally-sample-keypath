BUILD:=_build
FAKE_LIB:=libfakes.a

CFLAGS += -Wall -MMD -MP -ggdb -O0 -coverage 

PKG_CONF_LIBS=\
	wallycore \
	libsecp256k1
CFLAGS += `pkg-config --cflags $(PKG_CONF_LIBS)`
#LDFLAGS += `pkg-config --libs $(PKG_CONF_LIBS)`

MK := mkdir
RM := rm -rf
AR := ar
CPP:= g++
