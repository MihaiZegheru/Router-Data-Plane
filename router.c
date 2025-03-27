#include <arpa/inet.h>
#include <string.h>
#include "protocols.h"
#include "queue.h"
#include "lib.h"

#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP		0x0800	/* IP protocol */
#endif

#ifndef ETHERTYPE_ARP
#define ETHERTYPE_ARP 		0x0806  /* ARP protocol */
#endif

char cpybuf[100];

/* Routing table */
struct route_table_entry *route_table;
int route_table_len;

/* ARP table */
struct arp_table_entry *arp_table;
int arp_table_len;

struct packet_data {
	char *buf;
	size_t len;
	size_t interface;

	struct ether_hdr *eth_hdr;
	struct ip_hdr *ip_hdr;
	struct icmp_hdr *icmp_hdr;
};

struct packet_data packet_data_init(void *buf, size_t len, size_t interface) {
	struct packet_data pkt = {
		.buf = buf,
		.len = len,
		.interface = interface,
		.eth_hdr = (struct ether_hdr*)buf,
		.ip_hdr = (struct ip_hdr *)(buf + sizeof(struct ether_hdr)),
		.icmp_hdr = NULL
	};
	return pkt;
}

void packet_data_insert_icmp_hdr(struct packet_data *pkt) {
	/* Shift memory in order to make space for the ICMP header */
	memcpy(cpybuf, pkt->ip_hdr + sizeof(struct ip_hdr),
		   sizeof(struct icmp_hdr));
	memcpy(pkt->ip_hdr + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr),
		   cpybuf, sizeof(struct icmp_hdr));

	pkt->icmp_hdr = (struct icmp_hdr *)(pkt->buf + sizeof(struct ether_hdr) +
										sizeof(struct ip_hdr));

	/* Update IPv4 header to accomodate ICMP */
	pkt->ip_hdr->tot_len = htons(ntohs(pkt->ip_hdr->tot_len) +
								 sizeof(struct icmp_hdr));
	pkt->ip_hdr->proto = IPPROTO_ICMP;

	pkt->len += sizeof(struct icmp_hdr);
}

struct route_table_entry *get_best_route(uint32_t ip_dest) {
    struct route_table_entry *best_match = NULL;
    uint32_t dip = ntohl(ip_dest); 

    for (int i = 0; i < route_table_len; i++) {
        uint32_t prefix = ntohl(route_table[i].prefix);
        uint32_t mask = ntohl(route_table[i].mask);

        if ((dip & mask) == prefix) {
            if (!best_match || mask > ntohl(best_match->mask)) {
                best_match = &route_table[i];
            }
        }
    }
    return best_match;
}

struct arp_table_entry *get_arp_entry(uint32_t given_ip) {
    for (int i = 0; i < arp_table_len; i++) {
        if (arp_table[i].ip == given_ip) {
            return &arp_table[i];
        }
    }
    return NULL;
}

void initialise_tables(char* rpath) {
	/* Allocate memory for the route_table */
	route_table = malloc(sizeof(struct route_table_entry) * 64300);
	DIE(route_table == NULL, "malloc route_table");

	/* Allocate memory for the arp_table */
	arp_table = malloc(sizeof(struct arp_table_entry) * 10);
	DIE(arp_table == NULL, "malloc arp_table");
	
	/* Read the static routing table and the ARP table */
	route_table_len = read_rtable(rpath, route_table);
	arp_table_len = parse_arp_table("arp_table.txt", arp_table);
}

void handle_icmp(struct packet_data *pkt, uint8_t type, uint8_t code) {
	if (type) {
		packet_data_insert_icmp_hdr(pkt);
	}
	pkt->icmp_hdr->mtype = type;
	pkt->icmp_hdr->mcode = code;

	/* Update IPv4 header */
	pkt->ip_hdr->dest_addr = pkt->ip_hdr->source_addr;
	pkt->ip_hdr->source_addr = inet_addr(get_interface_ip(pkt->interface));
	pkt->ip_hdr->ttl = 64;

	/* Recompute ICMP checksum */
	pkt->icmp_hdr->check = 0;
	pkt->icmp_hdr->check = htons(checksum((uint16_t *)pkt->icmp_hdr,
										  pkt->len - sizeof(struct ether_hdr) - 
										  sizeof(struct ip_hdr)));

	/* Recompute IPv4 checksum */
	pkt->ip_hdr->checksum = 0;
	pkt->ip_hdr->checksum = htons(checksum((uint16_t *)pkt->ip_hdr,
										   sizeof(struct ip_hdr)));

	/* Update Ethernet header */
	memcpy(pkt->eth_hdr->ethr_dhost, pkt->eth_hdr->ethr_shost, 6);
	get_interface_mac(pkt->interface, pkt->eth_hdr->ethr_shost);
	pkt->eth_hdr->ethr_type = htons(ETHERTYPE_IP);

	/* Send the packet */
	send_to_link(pkt->len, pkt->buf, pkt->interface);

	printf("Package sent as ICMP.\n");
}

int check_icmp_for_self(struct packet_data *pkt) {
	if (pkt->ip_hdr->dest_addr == inet_addr(get_interface_ip(pkt->interface))) {
		pkt->icmp_hdr = (struct icmp_hdr *)(pkt->buf + 
											sizeof(struct ether_hdr) +
											sizeof(struct ip_hdr));
		return 1;
	}
	return 0;
}

void handle_ipv4(struct packet_data *pkt) {
	printf("Handling IPv4 packet.\n");

	/* Verify IP checksum */
	if (checksum((uint16_t *)pkt->ip_hdr, sizeof(struct ip_hdr)) != 0) {
		printf("Dropping packet: invalid checksum\n");
		return;
	}

	/* Check if we got an ICMP packet. */
	if (pkt->ip_hdr->proto == IPPROTO_ICMP && check_icmp_for_self(pkt)) {
		if (pkt->icmp_hdr->mtype == 8 && pkt->icmp_hdr->mcode == 0) {
			handle_icmp(pkt, 0, 0);
			return;
		}
	}

	/* Find the best route. Drop packet if fail. */
	struct route_table_entry* route = get_best_route(pkt->ip_hdr->dest_addr);
	if (!route) {
		printf("Dropping packet: No route found\n");
		handle_icmp(pkt, 3, 0);
		return;
	}

	/* Check TTL */
	if (pkt->ip_hdr->ttl <= 1) {
		printf("Dropping packet: TTL expired\n");\
		handle_icmp(pkt, 11, 0);
		return;
	}
	pkt->ip_hdr->ttl--;

	/* Recompute checksum */
	pkt->ip_hdr->checksum = 0;
	pkt->ip_hdr->checksum = htons(checksum((uint16_t *)pkt->ip_hdr,
										   sizeof(struct ip_hdr)));

	/* Get destination MAC address (static ARP table) */
	struct arp_table_entry* dest_mac = get_arp_entry(route->next_hop);
	if (!dest_mac) {
		printf("Dropping packet: MAC entry not found for IP %u\n",
			   route->next_hop);
		return;
	}

	/* Get source MAC address */
	get_interface_mac(route->interface, pkt->eth_hdr->ethr_shost);
	
	/* Update Ethernet header */
	memcpy(pkt->eth_hdr->ethr_dhost, dest_mac->mac, 6);

	/* Send the packet */
	send_to_link(pkt->len, pkt->buf, route->interface);

	printf("Package forwarded.\n");
}

int main(int argc, char *argv[]) {
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argv + 2, argc - 2);

	initialise_tables(argv[1]);

	while (1) {
		size_t interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		printf("Received packet\n");

		struct packet_data pkt = packet_data_init(buf, len, interface);

		/* Check for IPv4 or ARP packet, else drop packet. */
		if (ntohs(pkt.eth_hdr->ethr_type) == ETHERTYPE_IP) {
			handle_ipv4(&pkt);
		} else if (ntohs(pkt.eth_hdr->ethr_type) == ETHERTYPE_ARP) {

		} else {
			printf("Dropping packet: Protocol unknown\n");
			continue;
		}
	}
}

