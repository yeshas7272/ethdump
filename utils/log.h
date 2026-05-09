#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <unistd.h>

#define ANSI_RED "\033[31m"
#define ANSI_RESET "\033[0m"

/**
 * log_info  — informational message, printed to stdout.
 * log_error — error message, printed to stderr with file and line context.
 *
 * Usage:
 *   log_info("Starting capture on %s", ifname);
 *   log_error("Failed to open interface: %s", errbuf);
 */

#define log_info(fmt, ...) fprintf(stdout, fmt "\n", ##__VA_ARGS__)

#define log_error(fmt, ...)                                                                        \
    fprintf(stderr, "%s%s:%d: " fmt "\n%s", isatty(STDERR_FILENO) ? ANSI_RED : "", __FILE__,       \
            __LINE__, ##__VA_ARGS__, isatty(STDERR_FILENO) ? ANSI_RESET : "")

#endif /* LOG_H */