# dhcping

`dhcping` is a small tool that can be used to test whether a DHCP
server looks like it is working. It pretends to be a DHCP relay
that sends information about a client address as specified on the
command line. Any valid looking reply (even if it is a NAK) is
enough to make the test succeed.

The tools is intended to be used as the backend to a check command
in `relayd(8)` so you can create a highly available DHCP service.
