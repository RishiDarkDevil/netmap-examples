#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <linux/errqueue.h>
#include <linux/net_tstamp.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#define __USE_XOPEN
#include <unistd.h>
#include <time.h>
#include <stdio.h>
#include <stdbool.h>

#define UDP_MAX_LENGTH 1500

typedef struct {
  int fd;
  int port;
  int err_no;
  struct sockaddr_in local;
  struct sockaddr_in remote;
  struct timeval time_kernel;
  struct timeval time_user;
  int64_t prev_serialnum;
} socket_info;

double l2_to_l7_time_taken = 0;
long count = 0;

// Define rdtscll as an inline function
static inline void rdtscll(unsigned long long *val)
{
    unsigned int low, high;
    asm volatile("rdtsc" : "=a"(low), "=d"(high));
    *val = ((unsigned long long)high << 32) | low;
}

static int setup_udp_receiver(socket_info *inf, int port) {
  inf->port = port;
  inf->fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (inf->fd < 0) {
    inf->err_no = errno;
    fprintf(stderr, "setup_udp_server: socket failed: %s\n",
            strerror(inf->err_no));
    return inf->fd;
  }

  int timestampOn =
      SOF_TIMESTAMPING_RX_SOFTWARE | SOF_TIMESTAMPING_TX_SOFTWARE |
      SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_RX_HARDWARE |
      SOF_TIMESTAMPING_TX_HARDWARE | SOF_TIMESTAMPING_RAW_HARDWARE |
      // SOF_TIMESTAMPING_OPT_TSONLY |
      0;
  int r = setsockopt(inf->fd, SOL_SOCKET, SO_TIMESTAMPING, &timestampOn,
                     sizeof timestampOn);
  if (r < 0) {
    inf->err_no = errno;
    fprintf(stderr, "setup_udp_server: setsockopt failed: %s\n",
            strerror(inf->err_no));
    return r;
  }

  int on = 1;
  r = setsockopt(inf->fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof on);
  if (r < 0) {
    inf->err_no = errno;
    fprintf(stderr, "setup_udp_server: setsockopt2 failed: %s\n",
            strerror(inf->err_no));
    return r;
  }

  inf->local = (struct sockaddr_in){.sin_family = AF_INET,
                                    .sin_port = htons((uint16_t)port),
                                    .sin_addr.s_addr = htonl(INADDR_ANY)};
  r = bind(inf->fd, (struct sockaddr *)&inf->local, sizeof inf->local);
  if (r < 0) {
    inf->err_no = errno;
    fprintf(stderr, "setup_udp_server: bind failed: %s\n",
            strerror(inf->err_no));
    return r;
  }

  inf->prev_serialnum = -1;

  return 0;
}

static int setup_udp_sender(socket_info *inf, int port, char *address) {
  inf->port = port;
  inf->fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (inf->fd < 0) {
    inf->err_no = errno;
    fprintf(stderr, "setup_udp_client: socket failed: %s\n",
            strerror(inf->err_no));
    return inf->fd;
  }

  int timestampOn =
      SOF_TIMESTAMPING_RX_SOFTWARE | SOF_TIMESTAMPING_TX_SOFTWARE |
      SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_RX_HARDWARE |
      SOF_TIMESTAMPING_TX_HARDWARE | SOF_TIMESTAMPING_RAW_HARDWARE |
      // SOF_TIMESTAMPING_OPT_TSONLY |
      0;
  int r = setsockopt(inf->fd, SOL_SOCKET, SO_TIMESTAMPING, &timestampOn,
                     sizeof timestampOn);
  if (r < 0) {
    inf->err_no = errno;
    fprintf(stderr, "setup_udp_server: setsockopt failed: %s\n",
            strerror(inf->err_no));
    return r;
  }

  inf->remote = (struct sockaddr_in){.sin_family = AF_INET,
                                     .sin_port = htons((uint16_t)port)};
  r = inet_aton(address, &inf->remote.sin_addr);
  if (r == 0) {
    fprintf(stderr, "setup_udp_client: inet_aton failed\n");
    inf->err_no = 0;
    return -1;
  }

  inf->local = (struct sockaddr_in){.sin_family = AF_INET,
                                    .sin_port = htons(0),
                                    .sin_addr.s_addr = htonl(INADDR_ANY)};
  inf->prev_serialnum = -1;

  return 0;
}

static void handle_scm_timestamping(struct scm_timestamping *ts) {
    
    // struct timespec tsmp;

    // Measure current time using CLOCK_REALTIME
    // if (clock_gettime(CLOCK_REALTIME, &tsmp) == -1) {
    //    perror("clock_gettime");
    //    exit(1);
    // }

    // l2_to_l7_time_taken += tsmp.tv_nsec - ts->ts[0].tv_nsec; count++;

    // // L2 -> L7 time taken
    // printf("L2 -> L7 time taken: %ld.%09ld seconds\n",
    //        tsmp.tv_sec - ts->ts[0].tv_sec, tsmp.tv_nsec - ts->ts[0].tv_nsec);

    // printf("SW L2 timestamp: %lld.%.9lds\n", (long long)ts->ts[0].tv_sec, ts->ts[0].tv_nsec);
    // printf("HW SYNC L2 timestamp: %lld.%.9lds\n", (long long)ts->ts[1].tv_sec, ts->ts[1].tv_nsec);
    // printf("HW L2 timestamp: %lld.%.9lds\n", (long long)ts->ts[2].tv_sec, ts->ts[2].tv_nsec);

    // // Print the measured time
    // printf("SW L7 timestamp: %ld.%09lds\n", tsmp.tv_sec, tsmp.tv_nsec);
}

static void handle_time(struct msghdr *msg) {

  for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg); cmsg;
       cmsg = CMSG_NXTHDR(msg, cmsg)) {
    // printf("level=%d, type=%d, len=%zu\n", cmsg->cmsg_level, cmsg->cmsg_type, cmsg->cmsg_len);

    if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_RECVERR) {
      struct sock_extended_err *ext =
          (struct sock_extended_err *)CMSG_DATA(cmsg);
      printf("errno=%d, origin=%d\n", ext->ee_errno, ext->ee_origin);
      continue;
    }

    if (cmsg->cmsg_level != SOL_SOCKET)
      continue;

    switch (cmsg->cmsg_type) {
    case SO_TIMESTAMPNS: {
      struct scm_timestamping *ts = (struct scm_timestamping *)CMSG_DATA(cmsg);
      handle_scm_timestamping(ts);
    } break;
    case SO_TIMESTAMPING: {
      struct scm_timestamping *ts = (struct scm_timestamping *)CMSG_DATA(cmsg);
      handle_scm_timestamping(ts);
    } break;
    default:
      /* Ignore other cmsg options */
      break;
    }
  }
//   printf("-- End messages --\n");
}

static ssize_t udp_receive(socket_info *inf, char *buf, size_t len) {
  char ctrl[2048];
  struct iovec iov = (struct iovec){.iov_base = buf, .iov_len = len};
  struct msghdr msg = (struct msghdr){.msg_control = ctrl,
                                      .msg_controllen = sizeof ctrl,
                                      .msg_name = &inf->remote,
                                      .msg_namelen = sizeof inf->remote,
                                      .msg_iov = &iov,
                                      .msg_iovlen = 1};
  ssize_t recv_len = recvmsg(inf->fd, &msg, 0);
  
  // unsigned long long curr;
  // rdtscll(&curr);
  // printf("Recieved: %llu\n", curr);
 
  struct timespec tsmp;

  // Measure current time using CLOCK_REALTIME
  if (clock_gettime(CLOCK_REALTIME, &tsmp) == -1) {
     perror("clock_gettime");
     exit(1);
  }

  printf("%ld.%09ld\n", tsmp.tv_sec, tsmp.tv_nsec);

  gettimeofday(&inf->time_user, NULL);

  if (recv_len < 0) {
    inf->err_no = errno;
    fprintf(stderr, "udp_receive: recvfrom failed: %s\n",
            strerror(inf->err_no));
  }

  handle_time(&msg);

  return recv_len;
}

static ssize_t udp_send(socket_info *inf, char *buf, size_t len) {
  struct iovec iov = (struct iovec){.iov_base = buf, .iov_len = len};
  struct msghdr msg = (struct msghdr){.msg_name = &inf->remote,
                                      .msg_namelen = sizeof inf->remote,
                                      .msg_iov = &iov,
                                      .msg_iovlen = 1};
  gettimeofday(&inf->time_user, NULL);
  ssize_t send_len = sendmsg(inf->fd, &msg, 0);
  if (send_len < 0) {
    inf->err_no = errno;
    fprintf(stderr, "udp_send: sendmsg failed: %s\n", strerror(inf->err_no));
  }

  return send_len;
}

static ssize_t meq_receive(socket_info *inf, char *buf, size_t len) {
  struct iovec iov = (struct iovec){.iov_base = buf, .iov_len = len};
  char ctrl[2048];
  struct msghdr msg = (struct msghdr){.msg_control = ctrl,
                                      .msg_controllen = sizeof ctrl,
                                      .msg_name = &inf->remote,
                                      .msg_namelen = sizeof inf->remote,
                                      .msg_iov = &iov,
                                      .msg_iovlen = 1};
  ssize_t recv_len = recvmsg(inf->fd, &msg, MSG_ERRQUEUE);
  if (recv_len < 0) {
    inf->err_no = errno;
    if (errno != EAGAIN) {
      fprintf(stderr, "meq_receive: recvmsg failed: %s\n",
              strerror(inf->err_no));
    }
    return recv_len;
  }
  handle_time(&msg);

  return recv_len;
}

typedef struct {
  int64_t serialnum;

  int64_t user_time_serialnum;
  int64_t user_time;

  int64_t kernel_time_serialnum;
  int64_t kernel_time;

  size_t message_bytes;
} message_header;

static const size_t payload_max = UDP_MAX_LENGTH - sizeof(message_header);

static ssize_t generate_random_message(socket_info *inf, char *buf,
                                       size_t len) {
  if (len < sizeof(message_header)) {
    return -1;
  }
  message_header *header = (message_header *)buf;
  char *payload = (char *)(header + 1);
  size_t payload_len = (size_t)random() % (payload_max + 1);
  if (payload_len > len - sizeof(message_header)) {
    payload_len = len - sizeof(message_header);
  }
  for (size_t i = 0; i < payload_len; i++) {
    payload[i] = (char)random();
  }

  static int64_t serial_num = 0;
  *header = (message_header){
      .user_time_serialnum = inf->prev_serialnum,
      .user_time = inf->time_user.tv_sec * 1000000000L + inf->time_user.tv_usec,
      .kernel_time_serialnum = inf->prev_serialnum,
      .kernel_time =
          inf->time_kernel.tv_sec * 1000000000L + inf->time_kernel.tv_usec,
      .serialnum = serial_num,
      .message_bytes = payload_len};
  size_t total = payload_len + sizeof *header;

  printf("uts%5" PRId64 ": kt=%" PRId64 ", ut=%" PRId64 ", sn=%" PRId64
         ": s=%zu\n",
         header->user_time_serialnum, header->kernel_time, header->user_time,
         header->serialnum, total);

  inf->prev_serialnum = serial_num++;

  return (ssize_t)total;
}

static void sender_loop(char *host) {
  socket_info inf;
  int ret = setup_udp_sender(&inf, 8000, host);
  if (ret < 0) {
    return;
  }

  for (int i = 0; i < 2000; i++) {
    useconds_t t = random() % 2000000;
    usleep(t);
    char packet_buffer[4096];
    ssize_t len =
        generate_random_message(&inf, packet_buffer, sizeof packet_buffer);
    if (len < 0) {
      return;
    }
    udp_send(&inf, packet_buffer, (size_t)len);
    while (meq_receive(&inf, packet_buffer, sizeof packet_buffer) != -1) {
    }
  }
}

static void receiver_loop(void) {
  socket_info inf;
  int ret = setup_udp_receiver(&inf, 8000);
  if (ret < 0) {
    return;
  }

  while(true) {
    char packet_buffer[4096];
    udp_receive(&inf, packet_buffer, sizeof packet_buffer);
  }
    printf("Avg L2 -> L7 time taken: %f ns\n", l2_to_l7_time_taken / count);
}

#define USAGE "Usage: %s [-r | -s host]\n"

int main(int argc, char *argv[]) {
  if (argc < 2) {
    fprintf(stderr, USAGE, argv[0]);
    return 0;
  }

  if (0 == strcmp(argv[1], "-s")) {
    if (argc < 3) {
      fprintf(stderr, USAGE, argv[0]);
      return 0;
    }
    sender_loop(argv[2]);
  } else if (0 == strcmp(argv[1], "-r")) {
    receiver_loop();
  } else {
    fprintf(stderr, USAGE, argv[0]);
  }
}
