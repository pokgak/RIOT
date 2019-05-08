# Default Makefile, for host native GNRC-based networking

# name of your application
APPLICATION = gcoap_example

# If no BOARD is found in the environment, use this default:
BOARD ?= native

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../..

BOARD_INSUFFICIENT_MEMORY := arduino-duemilanove arduino-mega2560 arduino-uno \
                             chronos mega-xplained msb-430 msb-430h \
                             nucleo-f031k6 nucleo-f042k6 nucleo-l031k6 \
                             nucleo-f030r8 nucleo-f303k8 nucleo-f334r8 \
                             nucleo-l053r8 stm32f0discovery telosb \
                             waspmote-pro wsn430-v1_3b wsn430-v1_4 z1

## Uncomment to redefine port, for example use 61616 for RFC 6282 UDP compression.
#GCOAP_PORT = 5683
#CFLAGS += -DGCOAP_PORT=$(GCOAP_PORT)

## Uncomment to redefine request token length, max 8.
#GCOAP_TOKENLEN = 2
#CFLAGS += -DGCOAP_TOKENLEN=$(GCOAP_TOKENLEN)

# Include packages that pull up and auto-init the link layer.
# NOTE: 6LoWPAN will be included if IEEE802.15.4 devices are present
USEMODULE += gnrc_netdev_default
USEMODULE += auto_init_gnrc_netif
# Specify the mandatory networking modules
USEMODULE += gnrc_ipv6_default
USEMODULE += gcoap
# Additional networking modules that can be dropped if not needed
USEMODULE += gnrc_icmpv6_echo

# Use tinydtls's sock_dtls
USEMODULE += tinydtls_sock_dtls
USEMODULE += sock_dtls 	# FIXME: why it doesnt see this?
ifneq (,$(filter sock_dtls,$(USEMODULE)))
  GCOAP_PORT = 5684
  CFLAGS += -DGCOAP_PORT=$(GCOAP_PORT)
  INCLUDES += -I$(CURDIR)
  # This adds support for TLS_PSK_WITH_AES_128_CCM_8
  CFLAGS += -DDTLS_PSK
  # This adds support for TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8
  #CFLAGS += -DDTLS_ECC
  ifneq (,$(filter tinydtls,$(USEMODULE)))
    # Log level for the tinydtls package
    # Values: 0:EMERG (Default), 1:ALERT 2:CRIT 3:WARN 4:NOTICE 5:INFO 6:DEBUG
    TINYDTLS_LOG ?= 6
  endif
endif

# Required by gcoap example
USEMODULE += od
USEMODULE += fmt
# Add also the shell, some shell commands
USEMODULE += shell
USEMODULE += shell_commands
USEMODULE += ps

# FIXME: This is a temporary patch
# TinyDTLS <= 0.8.6 requires around 426 bytes in RAM.
CFLAGS += -DTHREAD_STACKSIZE_MAIN=\(2*THREAD_STACKSIZE_DEFAULT\)

# add support for using mrf24j40 with nucleo boards
ifeq (nucleo-f411re, $(BOARD))
    USEMODULE += mrf24j40
    CFLAGS += -DMRF24J40_PARAM_SPI=SPI_DEV\(0\)
    CFLAGS += -DMRF24J40_PARAM_SPI_CLK=SPI_CLK_5MHZ
    CFLAGS += -DMRF24J40_PARAM_CS=ARDUINO_PIN_10
    CFLAGS += -DMRF24J40_PARAM_INT=ARDUINO_PIN_7
    CFLAGS += -DMRF24J40_PARAM_RESET=ARDUINO_PIN_5

    #CFLAGS += -DRADIO_SUPPLY_SWITCH_PINT=ARDUINO_PIN_A2
endif

# Comment this out to disable code in RIOT that does safety checking
# which is not needed in a production environment but helps in the
# development process:
DEVELHELP ?= 1

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

include $(RIOTBASE)/Makefile.include
