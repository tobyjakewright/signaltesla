CC      ?= gcc
CFLAGS  := -O2 -Wall -Wextra -std=c11 \
           $(shell pkg-config --cflags libusb-1.0 libcrypto)
LDFLAGS := $(shell pkg-config --libs libusb-1.0 libcrypto)

TARGET  := wch_capture
SRCS    := wch_protocol.c ble_connection_follow.c ble_crypto.c \
           wch_ble_analyzer.c wch_capture.c
OBJS    := $(SRCS:.c=.o)

.PHONY: all clean install test

all: $(TARGET)

test:
	$(CC) -O2 -Wall -Wextra -Werror -pedantic -std=c11 \
		ble_connection_follow.c tests/test_ble_connection_follow.c \
		-o /tmp/wch_ble_connection_follow_test
	/tmp/wch_ble_connection_follow_test
	$(CC) -O2 -Wall -Wextra -Werror -pedantic -std=c11 \
		wch_protocol.c tests/test_wch_protocol.c \
		-o /tmp/wch_protocol_test
	/tmp/wch_protocol_test
	$(CC) -O2 -Wall -Wextra -Werror -pedantic -std=c11 \
		$(shell pkg-config --cflags libcrypto) \
		ble_crypto.c tests/test_ble_crypto.c \
		-o /tmp/wch_ble_crypto_test $(shell pkg-config --libs libcrypto)
	/tmp/wch_ble_crypto_test
	$(CC) -O2 -Wall -Wextra -Werror -pedantic -std=c11 \
		$(shell pkg-config --cflags libusb-1.0 libcrypto) \
		wch_protocol.c ble_connection_follow.c ble_crypto.c wch_ble_analyzer.c \
		tests/test_wch_decode.c \
		-o /tmp/wch_decode_test $(shell pkg-config --libs libusb-1.0 libcrypto)
	/tmp/wch_decode_test

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c wch_ble_analyzer.h wch_protocol.h ble_connection_follow.h ble_crypto.h
	$(CC) $(CFLAGS) -c -o $@ $<

install: $(TARGET)
	install -Dm755 $(TARGET)          $(DESTDIR)/usr/local/bin/$(TARGET)
	install -Dm644 99-wch-ble-analyzer.rules \
	    $(DESTDIR)/etc/udev/rules.d/99-wch-ble-analyzer.rules
	@echo "Run: sudo udevadm control --reload-rules && sudo udevadm trigger"

clean:
	rm -f $(OBJS) $(TARGET)
