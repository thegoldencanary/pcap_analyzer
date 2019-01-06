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
    // Usage and help
    std::string usage = "Usage: pcap_test [-st] [-b protocol] [-h [protocol] [-i ] [-i ip | \"ip1 ip2\"] [-x ip | \"ip1 ip2\"] [--filter-destination] [--help] -f filename";
    std::string help_text =
    "\n\
     This analyzer parses files formatted \n\
     in the pcap file format and provides statistics \n\
     on the packets within. \n\n\
     -f, --filename       Select file for input \n\
     -h, --histogram      Prints a histogram of \n\
                          the given protocol \n\
     -b, --byte-stream    Outputs to standard out the \n\
                          TCP byte stream \n\
     -i, --include-ip     Parses only the ip(s) given \n\
     -x, --exclude-ip     Ignores the ip(s) given \n\
     -s, --statistics     Prints to output statistics \n\
                          of the packets in the file \n\
     -t, --throughput     Prints the throughput of the \n\
                          given protocol datastream \n\
     --filter-destination Filters IPs by destination \n\
                          address instead of source \n\
     --help               Prints this help menu \n\
                          \n\
     For filtering multiple IP addresses, wrap space \n\
     seperated in \"\" (\"192.168.0.1 192.168.1.1\") \n\
     You may use only one type of filter at a time \n\
     \n\
     Viable protocols are: \n\
     tcp udp eth ip ip6 arp \n\
     \n\
     Note that some protocols will not have underlying \n\
     data and are not useful with -t or -b\n";

    // Flags and ip lists
    char *input_filename;
    bool histogram = false;
    bool bytestream = false;
    bool statistics = false;
    bool throughput = false;
    std::string h_protocol = PROTOCOL_TCP;
    std::string t_protocol = PROTOCOL_TCP;
    std::string b_protocol = PROTOCOL_TCP;
    int use_destinations = 0;
    std::vector<std::string> *exclude_ip = new std::vector<std::string>();
    std::vector<std::string> *include_ip = new std::vector<std::string>();

    // String representing available short options
    const char *optstring = "f:h:bi:x:st";

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
        {"throughput", no_argument, NULL, 't'},
        {"filter-destination", no_argument, &use_destinations, 1},
        {"help", no_argument, NULL, 'a'}
    };

    // Parse
    int longindex = 0;
    char value = 0;
    while( ( value = getopt_long( argc, argv, optstring, longopts, &longindex) ) != -1 )
    {
        switch( value )
        {
            case 'f': {
                input_filename = optarg;
                break;
            }
            case 'h': {
                histogram = true;
                h_protocol = optarg;
                break;
            }
            case 'b': {
                bytestream = true;
                break;
            }
            case 'i': {
                char *tokens = strtok( optarg, " " );
                while( tokens != NULL )
                {
                    std::string s = tokens;
                    if( s[0] == '"' )
                    {
                        s = s.substr( 0, s.length() + 1 );
                        s = s.substr( 1 );
                    }
                    include_ip->push_back(s);
                    tokens = strtok( NULL, " " );
                }
                break;
            }
            case 'x': {
                char *tokens = strtok( optarg, " " );
                while( tokens != NULL )
                {
                    std::string s = tokens;
                    if( s[0] == '"' )
                    {
                        s = s.substr( 0, s.length() + 1 );
                        s = s.substr( 1 );
                    }
                    exclude_ip->push_back(s);
                    tokens = strtok( NULL, " " );
                }
                break;
            }
            case 's': {
                statistics = true;
                break;
            }
            case 't': {
                throughput = true;
                t_protocol = optarg;
                break;
            }
            case 'a': {
                std::cout << help_text << std::endl;
                return 0;
            }
            default: {
                char unknown = optopt;
                std::cout << "Unknown option: " << unknown << "\n"
                          << usage << std::endl;
            }
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

    PacketParser* parser = new PacketParser( file_handle, use_destinations );
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
        parser->produceStats();
    }

    if( throughput )
    {
        parser->produceBandwidths( t_protocol );
    }

    if( histogram )
    {
        parser->produceHistogram( h_protocol, 0 );
    }

    if( bytestream )
    {
        uint64_t size = parser->getDataBytesCount( b_protocol );
        char data[size];
        parser->readBytes( data, size );
        for( int i = 0; i < size; i++ )
        {
            std::cout << data[i];
        }
    }
    return return_code;
}
