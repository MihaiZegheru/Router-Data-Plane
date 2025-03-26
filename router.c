#include <arpa/inet.h>
#include <string.h>
#include "protocols.h"
#include "queue.h"
#include "lib.h"

#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP		0x0800	/* IP protocol */
#endif

/* Routing table */
struct route_table_entry *route_table;
int route_table_len;

/* ARP table */
struct arp_table_entry *arp_table;
int arp_table_len;

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
	/* Allocate memory for the route_table and arp_table */
	route_table = malloc(sizeof(struct route_table_entry) * 64300);
	DIE(route_table == NULL, "malloc route_table");

	arp_table = malloc(sizeof(struct arp_table_entry) * 10);
	DIE(arp_table == NULL, "malloc arp_table");
	
	/* Read the static routing table and the ARP table */
	route_table_len = read_rtable(rpath, route_table);
	arp_table_len = parse_arp_table("arp_table.txt", arp_table);
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argv + 2, argc - 2);

	initialise_tables(argv[1]);

	while (1) {
		size_t interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		// TODO: Implement the router forwarding logic

		/* Note that packets received are in network order,
			any header field which has more than 1 byte will need to be conerted to
			host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
			sending a packet on the link, */

		printf("Packet received!\n");

		struct ether_hdr *eth_hdr = (struct ether_hdr*) buf;

		struct ip_hdr *ip_hdr = (struct ip_hdr*)(buf + sizeof(struct ether_hdr));

		// TODO: Change to accept other types.

		/* Check if we got an IPv4 packet, else drop packet. */
		if (eth_hdr->ethr_type != ntohs(ETHERTYPE_IP)) {
			printf("Ignored non-IPv4 packet\n");
			continue;
		}
		printf("Got an IPv4 packet.\n");

		/* Verify IP checksum */
        if (checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)) != 0) {
            printf("Dropping packet: invalid checksum\n");
            continue;
        }

		/* Find the best route. Drop packet if fail. */
		struct route_table_entry* route = get_best_route(ip_hdr->dest_addr);
		if (!route) {
			printf("Dropping packet: No route found\n");
			continue;
		}

		/* Check TTL */
        if (ip_hdr->ttl <= 1) {
            printf("Dropping packet: TTL expired\n");
            continue;
        }
        ip_hdr->ttl--;

        /* Recompute checksum */
		ip_hdr->checksum = 0;
        ip_hdr->checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)));

		/* Get destination MAC address (static ARP table) */
		struct arp_table_entry* dest_mac = get_arp_entry(route->next_hop);
		if (!dest_mac) {
			printf("Dropping packet: MAC entry not found for IP %u\n", route->next_hop);
			continue;
		}

		/* Get source MAC address */
		get_interface_mac(route->interface, eth_hdr->ethr_shost);
		
		/* Update Ethernet header */
		memcpy(eth_hdr->ethr_dhost, dest_mac->mac, 6);

		/* Send the packet */
		int res = send_to_link(len, buf, route->interface);

		printf("Package forwarded. %d\n", res);
	}
}

