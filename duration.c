/*
 * Copyright (C) 2013, all rights reserved by Gregory Burd <greg@burd.me>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * version 2 (MPLv2).  If a copy of the MPL was not distributed with this file,
 * you can obtain one at: http://mozilla.org/MPL/2.0/
 *
 * NOTES:
 *    - on some platforms this will require -lrt
 */

#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <sys/timeb.h>


/**
 * ts_ns()
 *
 * A 1970-01-01 epoch UTC time, 1 nanosecond (ns) resolution divide by 1B to
 * get time_t.
 */
static uint64_t ts_ns()
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000LL + (uint64_t)ts.tv_nsec;
}

/**
 * ts_msc()
 *
 * A 1970-01-01 epoch UTC time, 1 microsecond (mcs) resolution divide by 1M to
 * get time_t.
 */
static uint64_t ts_mcs()
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000LL + (uint64_t)ts.tv_nsec / 1000LL;
}

/**
 * ts_ms()
 *
 * A 1970-01-01 epoch UTC time, 1 millisecond (ms) resolution divide by 1000 to
 * get time_t.
 */
static uint64_t ts_ms()
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000LL + (uint64_t)ts.tv_nsec / 1000000LL;
}

#if defined(__i386__) || defined(__x86_64__)

/**
 * cpu_clock_ticks()
 *
 * A measure provided by Intel x86 CPUs which provides the number of cycles
 * (aka "ticks") executed as a counter using the RDTSC instruction.
 */
static inline uint64_t cpu_clock_ticks()
{
     uint32_t lo, hi;
     __asm__ __volatile__ (
          "xorl %%eax, %%eax\n"
          "cpuid\n"
          "rdtsc\n"
          : "=a" (lo), "=d" (hi)
          :
          : "%ebx", "%ecx" );
     return (uint64_t)hi << 32 | lo;
}

/**
 * cpu_clock_ticks_ns()
 *
 * An approximation of nanoseconds from CPU clock ticks.
 */
static uint64_t elapsed_cpu_clock_ticks_ns(uint64_t start)
{
    unsigned int overhead = 10;
    uint64_t cpu_clock_ticks_per_ms = 2300000000000LL;
    return (cpu_clock_ticks() - start - overhead) * cpu_clock_ticks_per_ms;
}


/**
 * cpu_clock_ticks_mcs()
 *
 * An approximation of microseconds from CPU clock ticks.
 */
static uint64_t elapsed_cpu_clock_ticks_mcs(uint64_t start)
{
    unsigned int overhead = 10;
    uint64_t cpu_clock_ticks_per_ms = 2300000000LL;
    return (cpu_clock_ticks() - start - overhead) * cpu_clock_ticks_per_ms;
}


/**
 * cpu_clock_ticks_ms()
 *
 * An approximation of milliseconds from CPU clock ticks.
 */
static uint64_t elapsed_cpu_clock_ticks_ms(uint64_t start)
{
    unsigned int overhead = 10;
    uint64_t cpu_clock_ticks_per_ms = 2300000LL;
    return (cpu_clock_ticks() - start - overhead) * cpu_clock_ticks_per_ms;
}

#endif

typedef struct {
     uint64_t then;
     uint64_t (*timestamp)(void);
} duration_t;

static inline uint64_t elapsed(duration_t *duration)
{
     uint64_t now = duration->timestamp();
     uint64_t elapsed = now - duration->then;
     duration->then = now;
     return elapsed;
}

#define DURATION(name, resolution) duration_t name = \
     {ts_##resolution(), ts_ ## resolution}

#define ELAPSED_DURING(result, resolution, block)       \
     do {                                               \
          DURATION(__x, resolution);                    \
          do block while(0);                            \
          *result = elapsed(&__x);                      \
     } while(0);

#define CYCLES_DURING(result, block)                    \
     do {                                               \
         uint64_t __begin = cpu_clock_ticks();          \
         do block while(0);                             \
         *result = cpu_clock_ticks() - __begin;         \
     } while(0);

int main() {
     uint64_t ns;
     uint64_t ticks;
     uint64_t cycles;
     ELAPSED_DURING(&ns, ns, { cpu_clock_ticks(); });
     CYCLES_DURING(&cycles, { printf("rdtsc: %lu (%lu ns)\n", ticks, ns); });
     printf("which took %lu CPU clock cycles to printf\n", cycles);
     return 0;
}
