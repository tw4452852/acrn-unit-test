ORG_DIR := .
C_SRCS_X86 := $(shell cd $(ORG_DIR) && ls x86/*.c x86/realmode/*.c)
C_SRCS_LIB := $(shell cd $(ORG_DIR) && ls lib/x86/*.c)

ALL_C_SRCS := $(C_SRCS_X86)
ALL_C_SRCS += $(C_SRCS_LIB)

FN_HEADER := $(shell cd $(ORG_DIR) && ls x86/64/*.c x86/32/*.c)

INCLUDE_PATH += x86
INCLUDE_PATH += x86/realmode
INCLUDE_PATH += x86/32
INCLUDE_PATH += x86/64
INCLUDE_PATH += lib
INCLUDE_PATH += lib/x86

C_CODESCAN := $(patsubst %.c,%.c.codescan,$(ALL_C_SRCS))
TMP_SCAN_OUT := $(shell mktemp /tmp/acrn-clang-tidy.XXXXX)
TMP_SCAN_ERR := $(shell mktemp /tmp/acrn-clang-tidy.XXXXX)
TMP_SCAN_FINAL := $(shell mktemp /tmp/acrn-clang-tidy.XXXXX)

ACRN_CHECK := acrn-c-st-02,acrn-c-ep-05,acrn-c-fn-05-06

codescan: $(C_CODESCAN)
	@if grep -q "warning:" $(TMP_SCAN_OUT) ; then \
        next=0; \
        cat $(TMP_SCAN_OUT) |while IFS= read -r line; \
        do \
                echo "$$line" | grep -q "^ "; \
                rst=$$?; \
                if [ $$next -gt 0 ]; then \
                        echo "$$line" >> $(TMP_SCAN_FINAL); \
                        next=$$((next-1)); \
                elif [[ $$rst -eq 1 && "$$line" =~ "warning:" && ! "$$line" = lib/* && ! "$$line" =~ "guest/lib/" && ! "$$line" =~ "guest/lib/x86/" ]]; then \
                        echo $$line >> $(TMP_SCAN_FINAL); \
                        next=2; \
                fi \
        done \
        fi
	@rm $(TMP_SCAN_OUT) $(TMP_SCAN_ERR)
	@if grep -q "warning:" $(TMP_SCAN_FINAL) ; then cat $(TMP_SCAN_FINAL); rm $(TMP_SCAN_FINAL); exit 1; else rm $(TMP_SCAN_FINAL); fi

$(C_CODESCAN): %.c.codescan: %.c $(FN_HEADER) 
	@echo "CODESCAN" $*.c
	@-clang-tidy $< -header-filter=.* --checks=-*,$(ACRN_CHECK) -- $(patsubst %, -I%, $(INCLUDE_PATH)) -I. -Wall -W -nostdlib -static -DSTACK_PROTECTOR -gdwarf-2 >> $(TMP_SCAN_OUT) 2>>$(TMP_SCAN_ERR)
