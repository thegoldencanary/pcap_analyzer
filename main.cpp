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
    // Usage string
    std::string usage = "Usage: pcap_test [-hbst] [-i include_ips..] [-x exclude_ips..] -f filename";

    // Flags and ip lists
    char *input_filename;
    bool histogram = false;
    bool bytestream = false;
    bool statistics = false;
    bool throughput = false;
    std::vector<char *> *exclude_ip = new std::vector<char *>();
    std::vector<char *> *include_ip = new std::vector<char *>();

    // String representing available short options
    const char *optstring = "f:hbi:x:st";

    // No err message
    opterr = 0;

    // Struct array of long options
    // { name, has_arg, flag, value }
    const struct option longopts[] =
    {
        {"filename", required_argument, NULL, 'f'},
        {"histogram", no_argument, NULL, 'h'},
        {"byte-stream", no_argument, NULL, 'b'},
        {"include-ip", required_argument, NULL, 'i'},
        {"exclude-ip", required_argument, NULL, 'x'},
        {"statistics", no_argument, NULL, 's'},
        {"throughput", no_argument, NULL, 't'}
    };

    // Parse
    int longindex = 0;
    char value = 0;
    while( ( value = getopt_long( argc, argv, optstring, longopts, &longindex) ) != -1 )
    {
        switch( value )
        {
            case 'f':
                input_filename = optarg;
                break;
            case 'h':
                histogram = true;
                break;
            case 'b':
                bytestream = true;
                break;
            case 'i':
                include_ip->push_back(optarg);
                break;
            case 'x':
                exclude_ip->push_back(optarg);
                break;
            case 's':
                statistics = true;
                break;
            case 't':
                throughput = true;
                break;
            default:
                char unknown = optopt;
                std::cout << "Unknown option: " << unknown << "\n"
                          << usage << std::endl;
        }
    }

    if( !include_ip->empty() && !exclude_ip->empty() )
    {
        std::cerr << "[-i --include-ip] and [-x --exclude-ip] are mutually exclusive"
        << std::endl;
        return 1;
    }

    // Open file and get handle
    pcap_t *file_handle;
    char error_buf[PCAP_ERRBUF_SIZE];
    file_handle = pcap_open_offline( input_filename, error_buf );
    if( file_handle == NULL )
    {
        std::cout << "Failed to open file: " << input_filename
                  << " " << error_buf << std::endl;
        return 1;
    }

    PacketParser* parser = new PacketParser( file_handle );
    try
    {
        parser->setExclusions( *exclude_ip );
        parser->setInclusions( *include_ip );
    }catch(InvalidIPAddressException& e)
    {
        std::cerr << "Could not parse filter list due to malformed IP address"
        << std::endl;
        return 1;
    }
    int return_code = parser->parsePackets(0);

    if( statistics )
    {

    }

    if( throughput )
    {

    }

    if( histogram )
    {
        parser->produceHistogram( 0, 0 );
    }

    if( bytestream )
    {

    }
    return return_code;
}
