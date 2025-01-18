/*
 * This program opens a netmap port and starts receiving packets,
 * counting all the UDP packets with a destination port specified
 * by command-line option.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <poll.h>
#include <net/if.h>
#include <stdint.h>
#include <net/netmap.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <time.h>

unsigned long long curr_cycle;

// Define rdtscll as an inline function
static inline void rdtscll(unsigned long long *val)
{
    unsigned int low, high;
    asm volatile("rdtsc" : "=a"(low), "=d"(high));
    *val = ((unsigned long long)high << 32) | low;
}

// Dump packets in hexadecimal form
void dump_packet(const unsigned char *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", buf[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
    }
    if (len % 16 != 0)
        printf("\n");
}

static int stop = 0;

static void
sigint_handler(int signum)
{
    stop = 1;
}

static inline int
udp_port_match(const char *buf, unsigned len, int udp_port)
{
    struct ether_header *ethh;
    struct ip *iph;
    struct udphdr *udph;

    ethh = (struct ether_header *)buf;
    if (ethh->ether_type != htons(ETHERTYPE_IP)) {
        /* Filter out non-IP traffic. */
        return 0;
    }
    iph = (struct ip *)(ethh + 1);
    if (iph->ip_p != IPPROTO_UDP) {
        /* Filter out non-UDP traffic. */
        return 0;
    }
    udph = (struct udphdr *)(iph + 1);

    /* Match the destination port. */
    if (udph->uh_dport == htons(udp_port)) {
        return 1;
    }

    return 0;
}

static int
main_loop(const char *netmap_port, int udp_port)
{

    struct nm_desc *nmd;
    unsigned long long cnt = 0;
    unsigned long long tot = 0;

    nmd = nm_open(netmap_port, NULL, 0, NULL);
    if (nmd == NULL) {
        if (!errno) {
            printf("Failed to nm_open(%s): not a netmap port\n", netmap_port);
        } else {
            printf("Failed to nm_open(%s): %s\n", netmap_port, strerror(errno));
        }
        return -1;
    }

    while (!stop) {
        unsigned int ri;
        int ret;

        /* We sync the user and kernel view of the ring non-blocking */
        ioctl(nmd->fd, NIOCRXSYNC, NULL);

        /* Scan all the receive rings. */
        for (ri = nmd->first_rx_ring; ri <= nmd->last_rx_ring; ri++) {
            struct netmap_ring *rxring;
            unsigned head, tail;
            int batch;

            rxring = NETMAP_RXRING(nmd->nifp, ri);
            head   = rxring->head;
            tail   = rxring->tail;
            batch  = tail - head;
            if (batch < 0) {
                batch += rxring->num_slots;
            }
            tot += batch;
            for (; head != tail; head = nm_ring_next(rxring, head)) {
                struct netmap_slot *slot = rxring->slot + head;
                char *buf                = NETMAP_BUF(rxring, slot->buf_idx);
		uint32_t len = slot->len;
		
		rdtscll(&curr_cycle);
		printf("%llu\n", curr_cycle);

		// printf("--- Packet Len %u ---\n", len);
                if (udp_port_match(buf, slot->len, udp_port)) {
                    cnt++;
		    // printf("--- This Packet is counted ---\n");  
		}
		dump_packet(buf, len);
            }
            rxring->cur = rxring->head = head;
	    
	    // rdtscll(&curr_cycle);
            // printf("%llu\n", curr_cycle);
	    
	    // struct timespec tsmp;

  	    // Measure current time using CLOCK_REALTIME
  	    // if (clock_gettime(CLOCK_REALTIME, &tsmp) == -1) {
      	    // 	perror("clock_gettime");
     	    //	exit(1);
  	    // }
	    // printf("%ld.%09ld\n", tsmp.tv_sec, tsmp.tv_nsec);	
        }
    }

    nm_close(nmd);
    printf("Total received packets: %llu\n", tot);
    printf("Counted packets       : %llu\n", cnt);

    return 0;
}

static void
usage(char **argv)
{
    printf("usage: %s [-h] [-p UDP_PORT] [-i NETMAP_PORT]\n", argv[0]);
    exit(EXIT_SUCCESS);
}

int
main(int argc, char **argv)
{
    const char *netmap_port = NULL;
    int udp_port            = 8000;
    struct sigaction sa;
    int opt;
    int ret;

    while ((opt = getopt(argc, argv, "hi:p:")) != -1) {
        switch (opt) {
        case 'h':
            usage(argv);
            return 0;

        case 'i':
            netmap_port = optarg;
            break;

        case 'p':
            udp_port = atoi(optarg);
            if (udp_port <= 0 || udp_port >= 65535) {
                printf("    invalid UDP port %s\n", optarg);
                usage(argv);
            }
            break;

        default:
            printf("    unrecognized option '-%c'\n", opt);
            usage(argv);
            return -1;
        }
    }

    if (netmap_port == NULL) {
        printf("    missing netmap port\n");
        usage(argv);
    }

    /* Register Ctrl-C handler. */
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    ret         = sigaction(SIGINT, &sa, NULL);
    if (ret) {
        perror("sigaction(SIGINT)");
        exit(EXIT_FAILURE);
    }

    printf("Port    : %s\n", netmap_port);
    printf("UDP port: %d\n", udp_port);

    main_loop(netmap_port, udp_port);

    (void)udp_port_match; /* silence the compiler */

    return 0;
}
