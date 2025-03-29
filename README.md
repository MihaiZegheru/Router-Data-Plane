# Router Data Plan

This is a C project for my Communication Protocols course's homework, where I 
have designed the data plane of a router featuring a dynamic ARP table and a
software efficient routing table search using a trie.

## About

The router supports IPv4, ICMP and ARP protocols over Ethernet.

### ARP

The router allows handling ARP requests, replies and submitting itself a 
request.

#### ARP request

Once the router receives a request, it fills in its interface's MAC address 
and sends the package back as an ARP Reply.

If the router needs to send a request because it cannot find the associated MAC 
address for an IP address, it will create an ARP request package and send it as 
broadcast to its neighbours.

#### ARP reply

Once the router receives an ARP reply, it will check its answer against its
ARP table and create a new entry if needed. It will then try to send all queued
up packets if their next hop MAC has been resolved, else they will be queued
back.

### IPv4

The IP protocol makes sure packets are forwarded correctly by performing the 
normal checks and updates on TTL. It tries to find the best route from a 
route table stored in as a trie for quick look up. The routes trie is always 
built at the begining of the execution, each branch following the order of the
bit mask. The search then prioritises longer masks.

If things go wrong and the router is not able to find a route for the packet
or the TTL has expired, it will issue and aggregate an ICMP packet and send it
back to the original sender.

### ICMP

The ICMP protocol is build over the IP one and it is only used for reporting
errors like `Expired TTL` or `Unreachable Host` back to the original sender. The
router will insert the ICMP header into the original packet, set the headers
accordingly and off it goes.

Moreover, the router will respond to the ICMP requests that it has received for
itself.
