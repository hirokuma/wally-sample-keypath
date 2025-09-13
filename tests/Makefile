BUILD:=_build
FFF_BUILD:=fff/build

BIN:=tst
SRCS:=\
	test_address.cpp \
	test_misc.cpp \
	test_tx.cpp \
	test_wallet.cpp \
	test_main.cpp
FILE_NAMES = $(notdir $(SRCS))
OBJECTS = $(addprefix $(BUILD)/, $(FILE_NAMES:.cpp=.o))
DEPS = $(OBJECTS:.o=.d)

FAKE_LIB:=libfakes.a
FAKES:=\
	fakes.cpp \
	fake_conf.cpp \
	fake_wally.cpp \
	fake_linux.cpp
FAKE_OBJECTS = $(addprefix $(BUILD)/, $(FAKES:.cpp=.o))
FAKE_DIRECTORIES = $(call rmdup, $(dir $(FAKE_OBJECTS)))
FAKE_DEPS = $(FAKE_OBJECTS:.o=.d)

# libwally-core usage test
BIN_WALLY:=tst_wally
SRCS_WALLY:=\
	test_wally.cpp \
	test_main.cpp

CFLAGS += -DUNIT_TEST -ggdb -O0 -coverage -DFFF_GCC_FUNCTION_ATTRIBUTES="__attribute__((weak))"
CFLAGS += -Wall -MMD -MP
CFLAGS += -I../src/include

PKG_CONF_LIBS=\
	wallycore \
	libsecp256k1
CFLAGS += `pkg-config --cflags $(PKG_CONF_LIBS)`
LDFLAGS += `pkg-config --libs $(PKG_CONF_LIBS)`

CFLAGS += -I$(FFF_BUILD)/_deps/googletest-src/googletest/include
LDFLAGS += -L$(BUILD) -lfakes -L$(FFF_BUILD)/lib -lgtest -lgtest_main -lm
LDFLAGS += -Wl,-Map=$(BUILD)/tst.map

MK := mkdir
RM := rm -rf
AR := ar
CPP:= g++

###########################################

all: mk_fff $(BUILD)/$(BIN)
	$(CPP) $(CFLAGS) -o $(BUILD)/$(BIN) $(SRCS) $(LDFLAGS) -pthread

ifeq ($(wildcard $(FFF_BUILD)),)
mk_fff: $(FFF_BUILD)
	cmake -S fff -B $(FFF_BUILD) -DFFF_GENERATE=ON -DFFF_UNIT_TESTING=ON && cmake --build $(FFF_BUILD)
else
mk_fff:
	@echo "$(FFF_BUILD) exists."
endif

$(FFF_BUILD):
	@$(MK) -p $@

$(BUILD)/$(BIN): $(BUILD) $(FAKE_OBJECTS) $(BUILD)/$(FAKE_LIB)

$(BUILD):
	@$(MK) -p $@

$(BUILD)/%.o: %.cpp
	$(CPP) $(CFLAGS) -c -o $@ $<

$(BUILD)/$(FAKE_LIB): $(FAKE_OBJECTS)
	@if [ ! -f $@ ] || [ $(shell find $(FAKE_OBJECTS) -newer $@ | wc -l) -gt 0 ]; then \
	  $(AR) -rv $@ $(FAKE_OBJECTS); \
	else \
	  echo "$@ is up to date."; \
	fi

test:
	$(BUILD)/$(BIN)
	@$(MK) -p $(BUILD)/coverage
	gcovr -r .. --html-details $(BUILD)/coverage/index.html -e $(FFF_BUILD) --delete --exclude-throw-branches

wally:
	$(CPP) $(CFLAGS) -o $(BUILD)/$(BIN_WALLY) $(SRCS_WALLY) $(LDFLAGS) -pthread
	$(BUILD)/$(BIN_WALLY)

# Include dependency files
-include $(DEPS)
-include $(FAKE_DEPS)

clean: 
	$(RM) $(BUILD)

mrproper:
	$(RM) $(FFF_BUILD) $(BUILD)
