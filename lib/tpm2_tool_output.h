#ifndef TPM2_TOOL_OUTPUT_H
#define TPM2_TOOL_OUTPUT_H

#include <stdio.h>

extern bool output_enabled;

/**
 * Output is enabled by default. This wrapper prevents code that
 * must disable output from accessing the global 'output_enabled'
 * variable directly.
 */
#define tpm2_tool_output_disable() (output_enabled = false)

/**
 * prints output to stdout respecting the quiet option.
 * Ie when quiet, don't print.
 * @param fmt
 *  The format specifier, ala printf.
 * @param ...
 *  The varargs, just like printf.
 */
#define tpm2_tool_output(fmt, ...)                   \
    do {                                        \
        if (output_enabled) {                   \
            printf(fmt, ##__VA_ARGS__);         \
        }                                       \
    } while (0)

#endif
