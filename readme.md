# C Sniffer for the Services Réseaux course

A program using the pcap library to capture network packets and the net / netinet libraries to analyse it.

Use `./bin/sniffer (-i interface | -o offline_file) -v verbose [-f filter]` to launch after `make`

`bootp.h` comes from : https://opensource.apple.com/source/tcpdump/tcpdump-1/tcpdump/bootp.h