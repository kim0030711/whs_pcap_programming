#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "myheader.h" // Include your custom header file
#include <netinet/ether.h> 
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        if (ip->iph_protocol == IPPROTO_TCP) {
            struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + (ip->iph_ihl << 2));

            printf("Ethernet Header: Source MAC: %02x:%02x:%02x:%02x:%02x:%02x, Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5],
                eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
            printf("IP Header: Source IP: %s, Destination IP: %s\n", inet_ntoa(ip->iph_sourceip), inet_ntoa(ip->iph_destip));
            printf("TCP Header: Source Port: %d, Destination Port: %d\n", ntohs(tcp->tcp_sport), ntohs(tcp->tcp_dport));

            int ip_header_len = (ip->iph_ihl & 0x0F) << 2;
            int tcp_header_len = (tcp->tcp_offx2 >> 4) << 2;
            int total_header_len = sizeof(struct ethheader) + ip_header_len + tcp_header_len;
            int payload_len = ntohs(ip->iph_len) - ip_header_len - tcp_header_len;

            if (payload_len > 0) {
                printf("Message: ");
                for (int i = total_header_len; i < total_header_len + payload_len && i < total_header_len + 16; i++) {
                    printf("%02x ", packet[i]);
                }
                printf("\n");
            }
        }
    }
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp"; // Capture only TCP packets
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name enp0s3 (Change the interface name as needed)
    handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);

    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle); // Close the handle
    return 0;