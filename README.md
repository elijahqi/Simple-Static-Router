# Simple Router 

This project implements a simple router that interacts directly with the routing table and handles packet forwarding.

## Overview

The `sr_router` project contains functions for initializing the routing subsystem, handling incoming packets, and managing the ARP cache. It processes both ARP and IP packets, forwarding packets to their intended destination or generating appropriate ICMP messages.

## Dependencies

This project relies on the following libraries:

- Standard C libraries: `stdio.h`, `assert.h`, `string.h`, and `stdlib.h`
- Custom libraries: `sr_if.h`, `sr_rt.h`, `sr_router.h`, `sr_protocol.h`, `sr_arpcache.h`, and `sr_utils.h`

## Getting Started

1. Clone the repository to your local machine.
2. Compile the project using a makefile.
3. Run the executable.

## Project Structure

The main file, `sr_router.c`, contains the following primary functions:

- `sr_init()`: Initializes the routing subsystem and the ARP cache cleanup thread.
- `sr_handlepacket()`: Called each time the router receives a packet on an interface. The function checks whether the packet is an IP or ARP packet and processes it accordingly.

## Acknowledgements

This project was initially created on Mon Feb 18 12:50:42 PST 2002. For any questions or concerns, please contact casado@stanford.edu.
