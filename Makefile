CROSS :=

ifneq ($(CROSS),)
CROSS_PREFIX := $(CROSS)-
endif

CC = $(CROSS_PREFIX)gcc
CFLAGS = -Wall -O2 -DTGT_A71CH -DOPENSSL -DSCP_MODE=C_MAC_C_ENC_R_MAC_R_ENC -DLINUX -DSCP_MODE=C_MAC_C_ENC_R_MAC_R_ENC -DPLATFORM_IMX
LFLAGS =
DFLAGS += -DTGT_A71CH
TARGET = get

all: $(TARGET)

$(TARGET): get.o smComSCI2C.o smCom.o sci2c.o i2c_a7.o sm_printf.o sm_timer.o sm_apdu.o sm_errors.o
	$(CC) $(LDFLAGS) $(CFLAGS) $^ $(LDLIBS) -o $@ -lssl -lcrypto

clean:
	$(RM) *~ *.o $(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

