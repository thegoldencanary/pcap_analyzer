#pragma once

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include <iostream>
#include <fstream>
#include <vector>
#include <unordered_map>
#include <sstream>
#include <exception>

#define PROTOCOL_TCP 0
#define PROTOCOL_IP 1
#define ETHERNET 2
#define PROTOCOL_UDP 3
#define PROTOCOL_IP6 4

// Ipv4 and ipv6 compatible struct
// family is AF_INET or AF_INET6
// address is actual representation of address
struct ip_address
{
    int family;
    char address[16];
};

struct InvalidIPAddressException : public std::exception {
   const char * what () const throw () {
      return "Invalid IP address";
   }
};

class PacketParser
{

public:

    // Constructor
    PacketParser(pcap_t *file_handle);

    // Set filter lists
    void setExclusions( std::vector<char *> ip );
    void setInclusions( std::vector<char *> ip );

    // Outputs histogram of given protocol
    // protocol is the netinet/in.h definition
    // bin_width is the bin width in microseconds
    void produceHistogram( uint32_t protocol, uint64_t bin_width );

    // Produces bandwidths for given protocol
    void produceBandwidths( uint32_t protocol );

    // Reads bytes of length bytes into the array at mem
    // from the internal data buffer
    void readBytes( char* mem, uint32_t bytes);

    // Parsing through number packets. 0 will read all packets
    int parsePackets( uint32_t number );

    // Getters
    std::vector<ip_address> * getInclusions();
    std::vector<ip_address> * getExclusions();

    uint32_t getPacketCount( uint32_t protocol );
    uint64_t getDataBytesCount( uint32_t protocol );
    uint64_t getTimeElapsed();
    uint64_t getBytesRead();
    uint64_t getPacketByteCount();

private:

    // File handle to capture file
    pcap_t* file_handle;

    // Filter lists
    std::vector<ip_address> include_ip;
    std::vector<ip_address> exclude_ip;

    // Hash maps of protocol, counts
    std::unordered_map<uint32_t, uint64_t> packet_counts;
    std::unordered_map<uint32_t, uint64_t> data_byte_counts;

    // Statistics
    uint64_t time_elapsed = 0;
    uint64_t bytes_elapsed = 0;
    uint64_t current_time = 0;
    uint64_t packet_time = 0;

    uint64_t packet_bytes = 0;

    // Internal TCP data buffer
    std::stringstream byte_buffer;

    // Parse methods for protocols
    // Takes pointer to packet, length of packet, and max length
    // (as given by the pcap header)
    void parseTCP( const u_char* packet, int length, int caplen );
    void parseUDP( const u_char* packet, int length, int caplen );

    // Checks filters and returns true if packet is to be filtered
    bool filter( ip_address dest_address );
};



