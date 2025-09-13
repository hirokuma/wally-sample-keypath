OUTPUT_FILENAME = tst
OUTPUT_BINARY_DIRECTORY = .

# source files
C_DIRECTORY = ./src
C_FILES += \
	src/address.c \
	src/conf.c \
	src/misc.c \
	src/tx.c \
	src/wallet.c \
	src/main.c

# object files
OBJECT_DIRECTORY = _build

CFLAGS += --std=gnu99 -Wall -Wextra -MMD -MP
CFLAGS += -Isrc/include

PKG_CONF_LIBS=\
	wallycore \
	libsecp256k1
CFLAGS += `pkg-config --cflags $(PKG_CONF_LIBS)`
LDFLAGS += `pkg-config --libs $(PKG_CONF_LIBS)` -lm

# default target - first one defined
#	debug
#	release
default: debug

###########################################

export OUTPUT_FILENAME
MAKEFILE_NAME := $(MAKEFILE_LIST)
MAKEFILE_DIR := $(dir $(MAKEFILE_NAME) )

MK := mkdir
RM := rm -rf

#echo suspend
ifeq ("$(VERBOSE)","1")
	NO_ECHO :=
else
	NO_ECHO := @
endif

# Toolchain commands
CC       		:= "$(GNU_PREFIX)gcc"
AS       		:= "$(GNU_PREFIX)as"
AR       		:= "$(GNU_PREFIX)ar" -r
LD       		:= "$(GNU_PREFIX)ld"
NM       		:= "$(GNU_PREFIX)nm"
OBJDUMP  		:= "$(GNU_PREFIX)objdump"
OBJCOPY  		:= "$(GNU_PREFIX)objcopy"
SIZE    		:= "$(GNU_PREFIX)size"

# function for removing duplicates in a list
# https://github.com/br101/pingcheck/blob/master/Makefile.default
rmdup = $(strip $(if $1,$(firstword $1) $(call rmdup,$(filter-out $(firstword $1),$1))))

#building all targets
all: debug

#target for printing all targets
help:
	@echo following targets are available:
	@echo 	debug release


C_SOURCE_FILES = $(addprefix $(C_DIRECTORY)/, $(C_FILES))
C_PATHS = $(call rmdup, $(dir $(C_SOURCE_FILES)))

C_OBJECTS = $(addprefix $(OBJECT_DIRECTORY)/, $(C_FILES:.c=.o))
DEPS = $(C_OBJECTS:.o=.d)
OBJECTS = $(C_OBJECTS)
OBJECTS_DIRECTORIES = $(call rmdup, $(dir $(OBJECTS)))

# Sorting removes duplicates
BUILD_DIRECTORIES := $(sort $(OBJECTS_DIRECTORIES) $(OUTPUT_BINARY_DIRECTORY))

vpath %.c $(C_PATHS)

debug: CFLAGS += -DDEBUG
debug: CFLAGS += -ggdb3 -O0
debug: LDFLAGS += -ggdb3 -O0
debug: $(OUTPUT_BINARY_DIRECTORY)/$(OUTPUT_FILENAME)

release: CFLAGS += -DNDEBUG -O3
release: LDFLAGS += -O3
release: $(OUTPUT_BINARY_DIRECTORY)/$(OUTPUT_FILENAME)

## Create build directories
$(BUILD_DIRECTORIES):
	@$(MK) -p $@

# Create objects from C SRC files
$(OBJECT_DIRECTORY)/%.o: %.c
	@echo Compiling C file: $(notdir $<): $(CFLAGS)
	$(NO_ECHO)$(CC) $(CFLAGS) -c -o $@ $<

# Link
$(OUTPUT_BINARY_DIRECTORY)/$(OUTPUT_FILENAME): $(BUILD_DIRECTORIES) $(OBJECTS)
	@echo Linking target: $(OUTPUT_FILENAME)
	$(NO_ECHO)$(CC) $(OBJECTS) $(LDFLAGS) -o $(OUTPUT_BINARY_DIRECTORY)/$(OUTPUT_FILENAME)

memcheck:
	valgrind --leak-check=full $(OUTPUT_BINARY_DIRECTORY)/$(OUTPUT_FILENAME)

# Include dependency files
-include $(DEPS)

clean:
	$(RM) $(OBJECT_DIRECTORY) $(OUTPUT_BINARY_DIRECTORY)/$(OUTPUT_FILENAME)
