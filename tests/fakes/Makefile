include ../common.mk

CFLAGS += -DFFF_GCC_FUNCTION_ATTRIBUTES="__attribute__((weak))"
CFLAGS += -I../../src/include -I../fff

FAKES:=\
	fakes.cpp \
	fake_address.cpp \
	fake_conf.cpp \
	fake_misc.cpp \
	fake_tx.cpp \
	fake_wallet.cpp \
	fake_wally.cpp \
	fake_linux.cpp
FAKE_OBJECTS = $(addprefix $(BUILD)/, $(FAKES:.cpp=.o))
FAKE_DEPS = $(FAKE_OBJECTS:.o=.d)

.PHONY: all

all: $(BUILD) $(BUILD)/$(FAKE_LIB)

$(BUILD):
	@$(MK) -p $@

$(BUILD)/$(FAKE_LIB): $(FAKE_OBJECTS)
	@echo "fakes archive"
	@$(AR) -rv $@ $(FAKE_OBJECTS)

$(BUILD)/%.o: %.cpp
	@echo "fakes compile: $< ..."
	@$(CPP) $(CFLAGS) -c -o $@ $<

-include $(FAKE_DEPS)
