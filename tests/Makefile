BUILD:=_build
FFF_BUILD:=fff/build

BIN:=tst
SRCS:=\
	../src/misc.c \
	test_address.cpp \
	test_wallet.cpp \
	test_main.cpp

# libwally-core usage test
BIN_WALLY:=tst_wally
SRCS_WALLY:=\
	test_wally.cpp \
	test_main.cpp

CFLAGS += -DUNIT_TEST -ggdb -O0 -coverage
CFLAGS += -Wall -MMD -MP
CFLAGS += -I../src/include

PKG_CONF_LIBS=\
	wallycore \
	libsecp256k1
CFLAGS += `pkg-config --cflags $(PKG_CONF_LIBS)`
LDFLAGS += `pkg-config --libs $(PKG_CONF_LIBS)`

CFLAGS += -I$(FFF_BUILD)/_deps/googletest-src/googletest/include
LDFLAGS += -L$(FFF_BUILD)/lib -lgtest -lgtest_main
LDFLAGS += -Wl,-Map=$(BUILD)/tst.map

all: mk_fff
	mkdir -p $(BUILD)
	g++ $(CFLAGS) -o $(BUILD)/$(BIN) $(SRCS) $(LDFLAGS) -pthread

ifeq ($(wildcard $(FFF_BUILD)),)
mk_fff:
	mkdir -p $(FFF_BUILD)
	cmake -S fff -B $(FFF_BUILD) -DFFF_GENERATE=ON -DFFF_UNIT_TESTING=ON && cmake --build $(FFF_BUILD)
else
mk_fff:
	@echo "$(FFF_BUILD) exists."
endif

test:
	$(BUILD)/$(BIN)
	mkdir -p $(BUILD)/coverage
	gcovr -r .. --html-details $(BUILD)/coverage/index.html -e $(FFF_BUILD) --delete --exclude-throw-branches

wally:
	g++ $(CFLAGS) -o $(BUILD)/$(BIN_WALLY) $(SRCS_WALLY) $(LDFLAGS) -pthread
	$(BUILD)/$(BIN_WALLY)

# Include dependency files
-include $(DEPS)

clean: 
	rm -rf $(BUILD)

mrproper:
	rm -rf $(FFF_BUILD) $(BUILD)
