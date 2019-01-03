#include <iostream>
#include <fstream>
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <vector>
#include <unordered_map>

// Parse and return info
std::string parse_packet( const struct pcap_pkthdr *header, const u_char *packet )
{
    // Setup our structs for holding header data
    const struct ether_header *eth_hdr;
    const struct ip *ip_hdr;
    const struct tcphdr *tcp_hdr;

    // Get the inital ethernet header
    eth_hdr = ( struct ether_header* ) packet;

    // Check the type of payload
    // If IP
    if( ntohs( eth_hdr->ether_type ) == ETHERTYPE_IP )
    {
        // Get IP header
        ip_hdr = ( struct ip* )( packet + sizeof(struct ether_header ) );

        // Check type of payload
        // If TCP
        if( ip_hdr->ip_p == IPPROTO_TCP )
        {
            // Get header
            tcp_hdr = ( tcphdr* )( packet + sizeof( struct ether_header )
                                + sizeof( struct ip ) );
            // Get pointer to data
            u_char *data;
            data = ( u_char * )( packet + sizeof( struct ether_header )
                                        + sizeof( struct ip )
                                        + sizeof( struct tcphdr ) );
            int length = header->caplen - sizeof( struct ether_header )
                                        - sizeof( struct ip )
                                        - sizeof( struct tcphdr );
            return std::string(data, data + length);
        }
        else
        {
            // Unsupported protocol, will return
            return "";
        }
    }else
    {
        // Unsupported ethertype, will return
        return "";
    }
}

int main( int argc, char **argv ) {

    // Parse args
    std::string help_text = "pcap_test filename source_ip";
    if( argc < 3 )
    {
        std::cout << "Invalid number of arguments" << std::endl;
        std::cout << help_text << std::endl;
        return 1;
    }
    char *input_filename = argv[1];
    char *source_ip = argv[2];

    pcap_t *file_handle;
    char error_buf[PCAP_ERRBUF_SIZE];

    // Open file
    file_handle = pcap_open_offline( input_filename, error_buf );
    if( file_handle == NULL )
    {
        std::cout << "Failed to open file: " << input_filename
                  << " " << error_buf << std::endl;
        return 1;
    }

    // Sniff packets
    const u_char *packet;
    struct pcap_pkthdr *header;
    while( 1 )
    {
        // Get next
        int return_code = pcap_next_ex( file_handle,
                                        &header,
                                        &packet);
        // Check if error or end
        // End of packets
        if( return_code < -1 )
        {
            break;
        }
        // Error occurred
        if( return_code == -1 )
        {
            std::cout << "Error occurred while reading: "
                        << pcap_geterr( file_handle ) << std::endl;
            return 1;
        }
        // If good, parse and output packet
        std::cout << parse_packet( header, packet ) << std::endl;
    }

    return 0;
}
