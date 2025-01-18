# Reciever on Ubuntu
gcc test.c -o test
./test -r

# Sender on Macos
nc -u 192.168.0.108 8000
# Now type anything and it will be sent

# Automated Sender on Macos (every 100ms of 1000 bytes UDP packet)
while true; do dd if=/dev/zero bs=1000 count=1 | nc -u -w1 192.168.0.108 8000; sleep 0.1; done

# Automated Sender Fast (Too Fast) on Macos - the userland and kernel space clock time differences behave wierdly
dd if=/dev/zero bs=1000 | nc -u -w1 192.168.0.108 8000

# To see exact times of when a `poll` is scheduled and when the packet is polled on the rx side.
# Unload the net driver module
sudo rmmod r8169
# Load the net driver module with timestamping injections for port `8000`
sudo insmod ../realtek_timestamp/realtek/r8169.ko
# View kernel logs
sudo dmesg -W
# Run this program for userland socket recv time
./test -r
# Run sender on Macos
# Compare time differences
