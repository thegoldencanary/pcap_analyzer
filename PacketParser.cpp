#include <algorithm>

#include "PacketParser.h"

PacketParser::PacketParser(pcap_t * file_handle, int filter_type)
    :file_handle( file_handle ),
    exclude_ip( std::vector<std::string>() ),
    include_ip( std::vector<std::string>() ),
    data_byte_counts( std::unordered_map<std::string, uint64_t>() ),
    packet_graph( std::vector<std::pair<std::string, uint64_t>>() ),
    filter_type( filter_type )
{
}

int PacketParser::parsePackets( uint32_t number )
{
    // Setup our structs for holding header data
    const u_char *packet;
    struct pcap_pkthdr *header;
    for( int packets = 0; (packets < number | number == 0); packets++ )
    {
        int return_code = pcap_next_ex( file_handle,
                                        &header,
                                        &packet);
        if( return_code < -1 )
        {
            return 0;
        }
        if( return_code == -1 )
        {
            std::cerr << "Error occurred while reading: "
                    << pcap_geterr( file_handle ) << std::endl;
            return 1;
        }

        std::vector<std::string> *packets_found = new std::vector<std::string>();
        const struct ether_header *eth_hdr;

        // Get the inital ethernet header
        eth_hdr = ( struct ether_header* ) packet;

        // Check the type of payload
        // If IP
        if( ntohs( eth_hdr->ether_type ) == ETHERTYPE_IP )
        {
            // Get IP header
            const struct ip *ip_hdr;
            ip_hdr = ( struct ip* )( packet + sizeof(struct ether_header ) );
            in_addr dest_address = ip_hdr->ip_dst;
            in_addr src_address = ip_hdr->ip_src;

            // Check filters
            char addr_d[INET_ADDRSTRLEN];
            char addr_s[INET_ADDRSTRLEN];
            int filter_count = 0;

            inet_ntop( AF_INET, &dest_address.s_addr, addr_d, INET_ADDRSTRLEN );
            inet_ntop( AF_INET, &src_address.s_addr, addr_s, INET_ADDRSTRLEN );
            if( filter_type == -1 )
            {
                filter_count += filter( std::string( addr_s ) );
            }
            else if( filter_type == 1 )
            {
                filter_count += filter( std::string( addr_d ) );
            }
            else
            {
                filter_count += filter( std::string( addr_d ) );
                filter_count += filter( std::string( addr_s ) );
            }
            if( filter_count > 0 )
            {
                continue;
            }

            // Check type of payload
            // If TCP
            if( ip_hdr->ip_p == IPPROTO_TCP )
            {
                int size = sizeof( struct ether_header )
                           + sizeof( struct ip );
                parseTCP( packet, size, header->caplen );
                packets_found->push_back(PROTOCOL_TCP);
            }
            else if( ip_hdr->ip_p == IPPROTO_UDP )
            {
                int size = sizeof( struct ether_header )
                           + sizeof( struct ip );
                parseUDP( packet, size, header->caplen );
                packets_found->push_back(PROTOCOL_UDP);
            }
            else
            {
                // Unsupported protocol, will return
                std::cerr << "Unsupported transport layer protocol" << std::endl;
                return 1;
            }

            packet_counts[PROTOCOL_IP] += 1;
            packets_found->push_back(PROTOCOL_IP);
            bytes_elapsed += sizeof( ip_hdr );

        }
        else if( ntohs( eth_hdr->ether_type ) == ETHERTYPE_IPV6 )
        {
            const struct ip6_hdr *ip_hdr;
            ip_hdr = ( struct ip6_hdr* )( packet + sizeof(struct ether_header ) );
            in6_addr dest_address = ip_hdr->ip6_dst;
            in6_addr src_address = ip_hdr->ip6_src;

            // Check filters
            char addr_d[INET6_ADDRSTRLEN];
            char addr_s[INET6_ADDRSTRLEN];
            int filter_count = 0;

            inet_ntop( AF_INET6, &dest_address, addr_d, INET6_ADDRSTRLEN );
            inet_ntop( AF_INET6, &src_address, addr_s, INET6_ADDRSTRLEN );
            if( filter_type == -1 )
            {
                filter_count += filter( std::string( addr_s ) );
            }
            else if( filter_type == 1 )
            {
                filter_count += filter( std::string( addr_d ) );
            }
            else
            {
                filter_count += filter( std::string( addr_d ) );
                filter_count += filter( std::string( addr_s ) );
            }
            if( filter_count > 0 )
            {
                continue;
            }

            // Check type of payload
            // If TCP
            if( ip_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_TCP )
            {
                int size = sizeof( struct ether_header )
                           + sizeof( struct ip6_hdr );
                parseTCP( packet, size, header->caplen );
            }
            else if( ip_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_UDP )
            {
                int size = sizeof( struct ether_header )
                           + sizeof( struct ip6_hdr );
                parseUDP( packet, size, header->caplen );
            }
            else
            {
                // Unsupported protocol, will return
                std::cerr << "Unsupported transport layer protocol" << std::endl;
                return 1;
            }

            packet_counts[PROTOCOL_IP6] += 1;
            packets_found->push_back(PROTOCOL_IP6);
            bytes_elapsed += sizeof( ip_hdr );

        }
        else
        {
            // Unsupported ethertype, will return
            std::cerr << "Unsupported link layer protocol" << std::endl;
            return 1;
        }
        // Update statistics
        packet_counts[ETHERNET] += 1;
        packets_found->push_back(ETHERNET);
        bytes_elapsed += sizeof( eth_hdr );
        packet_bytes += header->len;
        packet_time = header->ts.tv_sec * 1000000 + header->ts.tv_usec;
        if( current_time == 0 )
        {
            current_time = packet_time;
        }
        time_elapsed += packet_time - current_time;
        current_time = packet_time;
        for( auto x : *packets_found )
        {
            packet_graph.push_back(std::make_pair(x, time_elapsed));
        }
    }

    return 0;
}

bool PacketParser::filter( std::string address )
{
    for( auto x : exclude_ip )
    {
        if( x == address )
        {
            return true;
        }
    }
    if( !include_ip.empty() )
    {
        for( auto x : include_ip )
        {
            if( x == address )
            {
                return false;
            }
        }
        return true;
    }
    return false;
}

void PacketParser::parseTCP( const u_char* packet, int length, int caplen )
{
    // Get header
    const struct tcphdr *tcp_hdr;
    tcp_hdr = ( tcphdr* )( packet + length );

    // Get pointer to data
    int offset = (int) tcp_hdr->doff * 4;
    const char *data = ( const char * )( packet + sizeof( struct ether_header )
                                + sizeof( struct ip )
                                + offset );
    int size = caplen - sizeof( struct ether_header )
                                - sizeof( struct ip )
                                - sizeof( struct tcphdr );

    // Write data to buffer
    byte_buffer.write(data, size);

    // Update statistics
    packet_counts[PROTOCOL_TCP]+= 1;
    bytes_elapsed += sizeof( tcp_hdr );
    bytes_elapsed += size;
    data_byte_counts[PROTOCOL_TCP] += size;
}

void PacketParser::parseUDP(const u_char* packet, int length, int caplen)
{
    // Get header
    const struct udphdr *udp_hdr;
    udp_hdr = ( udphdr* )( packet + length );

    // Get pointer to data - no udp stream functionality for now, so
    // we won't write to buffer
    const char *data = ( const char * )( packet + sizeof( struct ether_header )
                                + sizeof( struct ip )
                                + sizeof( struct udphdr ) );
    int size = caplen - sizeof( struct ether_header )
                                - sizeof( struct ip )
                                - sizeof( struct udphdr );

    // Update statistics
    packet_counts[PROTOCOL_UDP]+= 1;
    bytes_elapsed += sizeof( udp_hdr );
    bytes_elapsed += size;
    data_byte_counts[PROTOCOL_UDP] += size;
}

void PacketParser::produceHistogram( std::string protocol, uint64_t bin_width )
{
    // Get protocol packets
    std::vector<uint64_t> *packets = new std::vector<uint64_t>();
    for( auto x : packet_graph )
    {
        if( std::get<0>( x ) == protocol )
        {
            packets->push_back( std::get<1>( x ) );
        }
    }

    if( packets->size() == 0 )
    {
        std::cout << "No packets of given protocol" << std::endl;
        return;
    }

    // Set default width of bins
    if( bin_width == 0 )
    {
        bin_width = packets->back() / sqrt( packets->size() );
    }

    // Get counts
    std::vector<uint64_t> *counts = new std::vector<uint64_t>();
    counts->push_back(0);
    int current_count = 0;
    uint64_t bin = bin_width;
    for( auto x : *packets )
    {
        if( x < bin )
        {
            counts->at(current_count) += 1;
        }
        else
        {
            current_count += 1;
            bin += bin_width;
            counts->push_back(1);
        }
    }

    // Print histogram
    bin = 0;
    uint64_t max_value = *std::max_element( counts->begin(), counts->end() );
    uint64_t bar_length = max_value / 32 + 1;
    for( auto x : *counts )
    {
        std::cout << bin << ":" << std::endl;
        std::cout << "\t";
        for( int i = 0; i < ( x / bar_length ) + 1; i++ )
        {
            std::cout << "=";
        }
        std::cout << " " << x << std::endl;
        bin += bin_width;
    }
    std::cout << bin << ":" << std::endl;
}

void PacketParser::produceBandwidths( std::string protocol )
{
    std::cout << std::endl;
    uint32_t bandwidth = 0;
    if( data_byte_counts[protocol] != 0 && time_elapsed != 0 )
    {
        bandwidth = data_byte_counts[protocol] /
                    ( time_elapsed / 1000000 );
    }
    std::cout << "Bandwidth: " << bandwidth << " bytes/s" << std::endl;
    std::cout << std::endl;
}

void PacketParser::produceStats()
{
    uint64_t data_byte_total = 0;
    for( std::pair<std::string, uint64_t> pair : packet_counts )
    {
        std::string x = std::get<0>( pair );
        std::cout << "Protocol: " << x << ": " << std::endl;
        std::cout << packet_counts[x] << " packets" << std::endl;
        if( data_byte_counts.count(x) )
        {
            data_byte_total += data_byte_counts[x];
            std::cout << "Payload bytes read: " << data_byte_counts[x] << std::endl;
        }
        std::cout << std::endl;
    }
    std::cout << "Read a total of " << bytes_elapsed << " bytes, "
    << data_byte_total << " of which were payload data bytes" << std::endl;
    std::cout << "Over " << time_elapsed / 1000000 << " seconds" << std::endl;
    std::cout << "Total bytes in real packets " << packet_bytes << std::endl;
}

void PacketParser::setExclusions( std::vector<std::string> ip )
{
    exclude_ip = ip;
}

void PacketParser::setInclusions( std::vector<std::string> ip )
{
    include_ip = ip;
}

void PacketParser::readBytes( char* mem, uint32_t bytes)
{
    byte_buffer.read(mem, bytes);
}

std::vector<std::string> * PacketParser::getInclusions()
{
    return &include_ip;
}

std::vector<std::string> * PacketParser::getExclusions()
{
    return &exclude_ip;
}

uint32_t PacketParser::getPacketCount( std::string protocol )
{
    return packet_counts[protocol];
}


uint64_t PacketParser::getTimeElapsed()
{
    return time_elapsed;
}

uint64_t PacketParser::getBytesRead()
{
    return bytes_elapsed;
}

uint64_t PacketParser::getDataBytesCount( std::string protocol )
{
    return data_byte_counts[protocol];
}

uint64_t PacketParser::getPacketByteCount()
{
    return packet_bytes;
}
