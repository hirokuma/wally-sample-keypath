include common.mk

FFF_BUILD:=fff/build

SRCS:=\
	test_address.cpp \
	test_misc.cpp \
	test_tx.cpp \
	test_wallet.cpp
FILE_NAMES = $(notdir $(SRCS))
OBJECTS = $(addprefix $(BUILD)/, $(FILE_NAMES:.cpp=.o))
TESTS = $(addprefix $(BUILD)/, $(FILE_NAMES:.cpp=))
DEPS = $(OBJECTS:.o=.d)

FAKES_DIR:=fakes
FAKES_SRCS := $(wildcard $(FAKES_DIR)/*.cpp)

# libwally-core usage test
BIN_WALLY:=tst_wally
SRCS_WALLY:=\
	test_wally.cpp \
	test_main.cpp

CFLAGS += -DUNIT_TEST
CFLAGS += -I../src/include -Ifff -Ifakes
CFLAGS += -I$(FFF_BUILD)/_deps/googletest-src/googletest/include

LDFLAGS += -L$(FAKES_DIR)/$(BUILD) -lfakes -L$(FFF_BUILD)/lib -lgtest -lgtest_main -lm

GCOVR_HTML = $(BUILD)/coverage/index.html
GCOVR_OPT = --gcov-delete --exclude-throw-branches --exclude-unreachable-branches --exclude-function-lines --exclude-noncode-lines

###########################################

all: mk_fff $(FAKES_DIR)/$(BUILD)/$(FAKE_LIB) $(BUILD) $(TESTS)

mk_fff:
	@if [ ! -d $(FFF_BUILD) ]; then \
		$(MK) -p $(FFF_BUILD); \
		cmake -S fff -B $(FFF_BUILD) -DFFF_GENERATE=ON -DFFF_UNIT_TESTING=ON && cmake --build $(FFF_BUILD); \
	fi

$(FAKES_DIR)/$(BUILD)/$(FAKE_LIB): $(FAKES_SRCS)
	make -C $(FAKES_DIR)

$(BUILD):
	@$(MK) -p $@

$(BUILD)/test_main.o:
	@echo "compile: test_main.cpp"
	@$(CPP) $(CFLAGS) -c -o $@ test_main.cpp

$(BUILD)/%.o: %.cpp
	@echo "compile: $< ..."
	@$(CPP) $(CFLAGS) -c -o $@ $<

#@$(CPP) $(CFLAGS) -o $(basename $@) $(basename $@).o $(BUILD)/test_main.o $(LDFLAGS)

$(TESTS): $(BUILD)/%: $(BUILD)/%.o $(BUILD)/test_main.o $(FAKES_DIR)/$(BUILD)/$(FAKE_LIB)
	@echo "link: $@"
	@$(CPP) $(CFLAGS) -o $@ $< $(BUILD)/test_main.o $(LDFLAGS)

tests: $(TESTS)
	@for t in $(TESTS); do \
		echo "Running $$t..."; \
		./$$t || exit 1; \
	done; \
	$(MK) -p $(BUILD)/coverage; \
	gcovr -r .. --html-details $(GCOVR_HTML) -e $(FFF_BUILD) $(GCOVR_OPT)

wally:
	$(CPP) $(CFLAGS) -o $(BUILD)/$(BIN_WALLY) $(SRCS_WALLY) $(LDFLAGS) -pthread
	$(BUILD)/$(BIN_WALLY)

clean: 
	$(RM) $(BUILD) $(FAKES_DIR)/$(BUILD)

mrproper: clean
	$(RM) $(FFF_BUILD)

# Include dependency files
-include $(DEPS)
