include common.mk

FFF_BUILD:=fff/build

# libwally-core usage test
BIN_WALLY:=tst_wally
SRCS_WALLY:=\
	test_wally.cpp \
	test_main.cpp

CFLAGS += -I../src/include -Ifff
CFLAGS += -I$(FFF_BUILD)/_deps/googletest-src/googletest/include

LDFLAGS += `pkg-config --libs $(PKG_CONF_LIBS)` -L$(FFF_BUILD)/lib -lgtest -lgtest_main -lm

###########################################

wally:
	$(CPP) $(CFLAGS) -o $(BUILD)/$(BIN_WALLY) $(SRCS_WALLY) $(LDFLAGS)
	$(BUILD)/$(BIN_WALLY)

clean: 
	$(RM) $(BUILD)/$(BIN_WALLY)
