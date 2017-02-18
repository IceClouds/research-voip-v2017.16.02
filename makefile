OBJS = config.o debug.o discover.o netbt.o registry.o replicate.o server.o
HDR = lwins.h

ifeq ($(COMPILER),clang)
CC = clang
FLAGS = -Werror
else
FLAGS = -rdynamic -O0 -g -Wall -Wextra -Werror -Wshadow -Wpointer-arith -Wcast-align \
	-Wwrite-strings -Wmissing-prototypes -Wmissing-declarations \
	-Wredundant-decls -Wnested-externs -Winline -Wno-long-long \
	-Wstrict-prototypes -Wformat=2 -fstack-protector-all
endif

.PHONY: all
all: lwins

.PHONY: test
test: lwins
	@echo [TEST] $<
	@sudo ./lwins --config lwins.conf

.PHONY: clean
clean:
	@$(RM) $(wildcard lwins $(OBJS))

lwins: $(OBJS)
	@echo [LD] $@
	@$(CC) -o lwins $(OBJS)

%.o: %.c $(HDR)
	@echo [CC] $<
	@$(CC) $(FLAGS) -I. -c $< -o $@

