#ifndef DEBUG_LOG_H_
#define DEBUG_LOG_H_

#include <stdio.h>
#include <stdint.h>

#ifndef UNIT_TEST
#define ENABLE_LOG_ERROR
#define ENABLE_LOG_WARN
#define ENABLE_LOG_INFO
#define ENABLE_LOG_DEBUG
#define ENABLE_LOG_TRACE
#else // UNIT_TEST
// #define ENABLE_LOG_ERROR
// #define ENABLE_LOG_WARN
// #define ENABLE_LOG_INFO
// #define ENABLE_LOG_DEBUG
// #define ENABLE_LOG_TRACE
#endif // UNIT_TEST

#define ANSI_ESC_RESET   "\033[0m"
#define ANSI_ESC_RED     "\033[31m"
#define ANSI_ESC_GREEN   "\033[32m"
#define ANSI_ESC_YELLOW  "\033[33m"
#define ANSI_ESC_BLUE    "\033[34m"
#define ANSI_ESC_MAGENTA "\033[35m"
#define ANSI_ESC_CYAN    "\033[36m"
#define ANSI_ESC_WHITE   "\033[37m"
#define ANSI_ESC_DARK    "\033[38;5;240m"

#ifdef ENABLE_LOG_ERROR
#define LOGE(fmt, args...) \
    fprintf(stderr, ANSI_ESC_RED "E[%s %s:%d]" fmt ANSI_ESC_RESET "\n", __PRETTY_FUNCTION__, __FILE__, __LINE__,## args)
#else   //ENABLE_LOG_ERROR
#define LOGE(fmt, args...)
#endif  //ENABLE_LOG_ERROR


#ifdef ENABLE_LOG_WARN
#define LOGW(fmt, args...) \
    fprintf(stderr, ANSI_ESC_YELLOW "W[%s %s:%d]" fmt ANSI_ESC_RESET "\n", __PRETTY_FUNCTION__, __FILE__, __LINE__,## args)
#else   //ENABLE_LOG_WARN
#define LOGW(fmt, args...)
#endif  //ENABLE_LOG_WARN


#ifdef ENABLE_LOG_INFO
#define LOGI(fmt, args...) \
    fprintf(stderr, ANSI_ESC_CYAN "I[%s %s:%d]" fmt ANSI_ESC_RESET "\n", __PRETTY_FUNCTION__, __FILE__, __LINE__,## args)
#else   //ENABLE_LOG_INFO
#define LOGI(fmt, args...)
#endif  //ENABLE_LOG_INFO


#ifdef ENABLE_LOG_DEBUG
#define LOGD(fmt, args...) \
    fprintf(stderr, ANSI_ESC_MAGENTA "D[%s %s:%d]" fmt ANSI_ESC_RESET "\n", __PRETTY_FUNCTION__, __FILE__, __LINE__,## args)

#pragma GCC diagnostic ignored "-Wunused-function"
static void DUMPD(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        fprintf(stderr, ANSI_ESC_MAGENTA "%02x", data[i]);
    }
    fprintf(stderr, ANSI_ESC_RESET "\n");
}
#pragma GCC diagnostic pop

#else   //ENABLE_LOG_DEBUG
#define LOGD(fmt, args...)
#define DUMPD(...)
#endif  //ENABLE_LOG_DEBUG


#ifdef ENABLE_LOG_TRACE
#define LOGT(fmt, args...) \
    fprintf(stderr, ANSI_ESC_DARK "T[%s %s:%d]" fmt ANSI_ESC_RESET "\n", __PRETTY_FUNCTION__, __FILE__, __LINE__,## args)


#pragma GCC diagnostic ignored "-Wunused-function"
static void DUMPT(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        fprintf(stderr, ANSI_ESC_DARK "%02x", data[i]);
    }
    fprintf(stderr, ANSI_ESC_RESET "\n");
}
#pragma GCC diagnostic pop

#else   //ENABLE_LOG_TRACE
#define LOGT(fmt, args...)
#define DUMPT(...)
#endif  //ENABLE_LOG_TRACE

#endif /* DEBUG_LOG_H_ */
