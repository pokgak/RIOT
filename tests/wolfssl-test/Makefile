APPLICATION = wolfssl-test

# If no BOARD is found in the environment, use this default:
BOARD ?= native

# Only 32-bit targets
BOARD_BLACKLIST := arduino-duemilanove arduino-leonardo \
                   arduino-mega2560 arduino-nano \
                   arduino-uno chronos esp8266-esp-12x esp8266-olimex-mod \
                   esp8266-sparkfun-thing jiminy-mega256rfr2 mega-xplained \
                   msb-430 msb-430h telosb waspmote-pro \
                   wsn430-v1_3b wsn430-v1_4 z1

# BOARD_INSUFFICIENT_MEMORY:= None known :)
#
# If the test fails to run on a target, disable the algorithms
# that you do not plan to use, by removing the associated wolfcrypt_* modules
# from USEMODULE list below.
#
# BOARD_INSUFFICIENT_MEMORY :=

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../..

# Used for inserting debug symbols into library for portability
# testing on Ubuntu 16.04 LTS w/ gcc v 5.4.0
#CFLAGS += -g
#LDFLAGS += -g

# Necessary to set the stacksize on Ubuntu Native device when using
# gcc v 5.4.0 on 16.04 LTS
# This is an optimized stack value based on testing, if you observe
# a segmentation fault please increase this stack size.
CFLAGS += -DTHREAD_STACKSIZE_MAIN=35000

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1


USEPKG += wolfssl
USEMODULE += wolfcrypt wolfcrypt-test wolfcrypt_sha512 wolfcrypt_curve25519  \
			 wolfcrypt_ed25519 wolfcrypt_chacha wolfcrypt_poly1305 wolfcrypt_aes \
			 wolfcrypt_ecc wolfcrypt_asn wolfcrypt_random

# Comment the following line to disable full-benchmark test
USEMODULE += wolfcrypt-benchmark

ifneq ($(BOARD),native)
  CFLAGS += -DBENCH_EMBEDDED
endif

include $(RIOTBASE)/Makefile.include
