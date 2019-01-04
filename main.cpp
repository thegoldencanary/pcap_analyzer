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
#include <getopt.h>

#include "PacketParser.h"

int main( int argc, char **argv ) {

    // Parse args
    std::string usage = "Usage: pcap_test [-hbst] [-p protocol..] [-i include_ips..] [-x exclude_ips..] -f filename";
    opterr = 0;

    // String representing available short options
    const char *optstring = "f:hbp:i:x:st";

    // Struct array of long options
    // { name, has_arg, flag, value }
    const struct option longopts[] =
    {
        {"filename", required_argument, NULL, 'f'},
        {"histogram", no_argument, NULL, 'h'},
        {"bytes", no_argument, NULL, 'b'},
        {"protocols", required_argument, NULL, 'p'},
        {"include-ip", required_argument, NULL, 'i'},
        {"exclude-ip", required_argument, NULL, 'x'},
        {"statistics", no_argument, NULL, 's'},
        {"throughput", no_argument, NULL, 't'}
    };

    int longindex = 0;
    char value = 0;
    while( ( value = getopt_long( argc, argv, optstring, longopts, &longindex) ) != -1 )
    {
        switch( value )
        {
            case 'f':
                break;
            case 'h':
                break;
            case 'b':
                break;
            case 'p':
                break;
            case 'i':
                break;
            case 'x':
                break;
            case 's':
                break;
            case 't':
                break;
            default:
                char unknown = optopt;
                std::cout << "Unknown option: " << unknown << "\n"
                          << usage << std::endl;
        }
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

    PacketParser* parser = new PacketParser( file_handle );
    in_addr ip_to_filter;
    inet_pton( AF_INET, "192.168.2.20", &ip_to_filter);
    int return_code = parser->parsePackets(0);
    std::cout << "IP: " << parser->getIPCount() << std::endl;
    std::cout << "Ethernet: " << parser->getEthCount() << std::endl;
    std::cout << "TCP: " << parser->getTCPCount() << std::endl;
    std::cout << std::endl;
    std::cout << "Bytes read: " << parser->getBytesRead() << std::endl;
    std::cout << "TCP Bytes Read: " << parser->getTCPBytesRead() << std::endl;
    std::cout << "Length of packet data: " << parser->getPacketByteCount() << std::endl;
    std::cout << "Time elapsed: " << parser->getTimeElapsed() / 1000000 << std::endl;
    parser->produceBandwidths();
    return return_code;
}
