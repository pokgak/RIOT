/*
 * Copyright (C) 2008, 2009, 2010 Kaspar Schleiser <kaspar@schleiser.de>
 * Copyright (C) 2013 INRIA
 * Copyright (C) 2013 Ludwig Knüpfer <ludwig.knuepfer@fu-berlin.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       Default application that shows a lot of functionality of RIOT
 *
 * @author      Kaspar Schleiser <kaspar@schleiser.de>
 * @author      Oliver Hahm <oliver.hahm@inria.fr>
 * @author      Ludwig Knüpfer <ludwig.knuepfer@fu-berlin.de>
 *
 * @}
 */

#include <stdio.h>
#include <string.h>

#include "shell.h"
#include "ztimer.h"
#include "test_utils/expect.h"

extern int test_cmd(int argc, char **argv);
extern int empty_cmd(int argc, char **argv);

static const shell_command_t shell_commands[] = {
    { "test", "test cmd", test_cmd },
    { "empty", "empty cmd", empty_cmd },
    { NULL, NULL, NULL }
};

static void cb(void *arg)
{
    (void)arg;
    puts("THIS SHOULD NEVER TRIGGERS!");
    expect(false);
}

int empty_cmd(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    return 0;
}

int test_cmd(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    ztimer_t stack_timer = {
        .callback = cb,
    };

    ztimer_set(ZTIMER_USEC, &stack_timer, 1000000);
    ztimer_remove(ZTIMER_USEC, &stack_timer);

    ztimer_set(ZTIMER_USEC, &stack_timer, 1000000);
    ztimer_remove(ZTIMER_USEC, &stack_timer);

    return 0;
}

int main(void)
{
    (void) puts("Welcome to RIOT!");

    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    return 0;
}
