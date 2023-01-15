# C Sniffer for the Services Réseaux course

[![Build CI](https://github.com/FelixLusseau/sniffer/actions/workflows/Build.yml/badge.svg)](https://github.com/FelixLusseau/sniffer/actions/workflows/Build.yml)
[![Author](https://img.shields.io/badge/author-@FelixLusseau-blue)](https://github.com/FelixLusseau)

A program using the pcap library to capture network packets and the net / netinet libraries to analyse it.

Use `./bin/sniffer (-i interface | -o offline_file) -v verbose [-f filter]` to launch after `make`

`bootp.h` comes from : https://opensource.apple.com/source/tcpdump/tcpdump-1/tcpdump/bootp.h
