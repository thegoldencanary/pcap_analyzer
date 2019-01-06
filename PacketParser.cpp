#include <algorithm>

#include "PacketParser.h"

PacketParser::PacketParser(pcap_t * file_handle)
    :file_handle( file_handle ),
    exclude_ip( std::vector<ip_address>() ),
    include_ip( std::vector<ip_address>() )
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
            ip_address filter_address;
            filter_address.family = AF_INET;
            memcpy( &filter_address.address + 12, &dest_address.s_addr, 4 );
            if( filter( filter_address ) )
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
            }
            if( ip_hdr->ip_p == IPPROTO_UDP )
            {
                int size = sizeof( struct ether_header )
                           + sizeof( struct ip );
                parseUDP( packet, size, header->caplen );
            }
            else
            {
                // Unsupported protocol, will return
                return -1;
            }

            packet_counts[PROTOCOL_IP] += 1;
            bytes_elapsed += sizeof( ip_hdr );

        }
        if( ntohs( eth_hdr->ether_type ) == ETHERTYPE_IPV6 )
        {
            const struct ip6_hdr *ip_hdr;
            ip_hdr = ( struct ip6_hdr* )( packet + sizeof(struct ether_header ) );
            in6_addr dest_address = ip_hdr->ip6_dst;
            in6_addr src_address = ip_hdr->ip6_src;

            // Check filters
            ip_address filter_address;
            filter_address.family = AF_INET6;
            memcpy( &filter_address.address, &dest_address, 16 );
            if( filter( filter_address ) )
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
            if( ip_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_UDP )
            {
                int size = sizeof( struct ether_header )
                           + sizeof( struct ip6_hdr );
                parseUDP( packet, size, header->caplen );
            }
            else
            {
                // Unsupported protocol, will return
                return -1;
            }

            packet_counts[PROTOCOL_IP6] += 1;
            bytes_elapsed += sizeof( ip_hdr );

        }
        if( ntohs( eth_hdr->ether_type ) == ETHERTYPE_ARP )
        {
            const struct arphdr *arp_hdr;
            arp_hdr = ( struct arphdr* ) ( packet + sizeof(struct ether_header ) );
            int size = ( arp_hdr->ar_hln + arp_hdr->ar_pln ) * 2;
            packet_counts[PROTOCOL_ARP] += 1;
            bytes_elapsed += sizeof( arp_hdr );
            bytes_elapsed += size;
        }
        else
        {
            // Unsupported ethertype, will return
            return -1;
        }
        packet_counts[ETHERNET] += 1;
        bytes_elapsed += sizeof( eth_hdr );
        packet_bytes += header->len;
        packet_time = header->ts.tv_sec * 1000000 + header->ts.tv_usec;
        if( current_time == 0 )
        {
            current_time = packet_time;
        }
        time_elapsed += packet_time - current_time;
        current_time = packet_time;
    }

    return 0;
}

bool PacketParser::filter( ip_address dest_address )
{
    int offset = 12;
    int length = 4;
    bool ip6 = false;
    if( dest_address.family == AF_INET6 )
    {
        offset = 0;
        length = 16;
        ip6 = true;
    }
    for( auto x : exclude_ip )
    {
        if( ip6 && x.family == AF_INET )
        {
            continue;
        }
        if( !memcmp( &dest_address.address + offset, x.address + offset, length ) )
        {
            return true;
        }
    }
    if( !include_ip.empty() )
    {
        for( auto x : include_ip )
        {
            if( ip6 && x.family == AF_INET )
            {
                continue;
            }
            if( !memcmp( &dest_address.address + offset, x.address + offset, length ) )
            {
                return false;
            }
        }
    }
    return false;
}

void PacketParser::parseTCP( const u_char* packet, int length, int caplen )
{
    // Get header
    const struct tcphdr *tcp_hdr;
    tcp_hdr = ( tcphdr* )( packet + length );
    // Get pointer to data
    const char *data = ( const char * )( packet + sizeof( struct ether_header )
                                + sizeof( struct ip )
                                + sizeof( struct tcphdr ) );
    int size = caplen - sizeof( struct ether_header )
                                - sizeof( struct ip )
                                - sizeof( struct tcphdr );

    byte_buffer.write(data, size);

    packet_counts[PROTOCOL_TCP]+= 1;
    bytes_elapsed += sizeof( tcp_hdr );
    bytes_elapsed += size;
    data_byte_counts[PROTOCOL_TCP] += size;
}

void PacketParser::parseUDP(const u_char* packet, int length, int caplen)
{
    const struct udphdr *udp_hdr;
    udp_hdr = ( udphdr* )( packet + length );
    // Get pointer to data
    const char *data = ( const char * )( packet + sizeof( struct ether_header )
                                + sizeof( struct ip )
                                + sizeof( struct udphdr ) );
    int size = caplen - sizeof( struct ether_header )
                                - sizeof( struct ip )
                                - sizeof( struct udphdr );

    packet_counts[PROTOCOL_UDP]+= 1;
    bytes_elapsed += sizeof( udp_hdr );
    bytes_elapsed += size;
    data_byte_counts[PROTOCOL_UDP] += size;
}

void PacketParser::setExclusions( std::vector<char *> ip )
{
    std::vector<ip_address> ips;
    for( auto x : ip )
    {
        ip_address address;
        int result = inet_pton( AF_INET, x, address.address + 12 );
        address.family = AF_INET;
        if( result == 0 )
        {
            result = inet_pton( AF_INET6, x, address.address );
            address.family = AF_INET6;
        }
        if( !result )
        {
            throw InvalidIPAddressException();
        }
        ips.push_back(address);
    }
    exclude_ip = ips;
}

void PacketParser::setInclusions( std::vector<char *> ip )
{
    std::vector<ip_address> ips;
    for( auto x : ip )
    {
        ip_address address;
        int result = inet_pton( AF_INET, x, address.address + 12 );
        address.family = AF_INET;
        if( result == 0 )
        {
            result = inet_pton( AF_INET6, x, address.address );
            address.family = AF_INET6;
        }
        if( !result )
        {
            throw InvalidIPAddressException();
        }
        ips.push_back(address);
    }
    include_ip = ips;
}

void PacketParser::produceHistogram( uint32_t protocol, uint64_t bin_width )
{
    if( protocol == IPPROTO_TCP )
    {

    }
}

void PacketParser::produceBandwidths( uint32_t protocol )
{
    uint32_t bandwidth = 0;
    if( data_byte_counts[protocol] != 0 && time_elapsed != 0 )
    {
        bandwidth = data_byte_counts[protocol] /
                    ( time_elapsed / 1000000 );
    }
    std::cout << "Bandwidth: " << bandwidth << " bytes/s" << std::endl;
    std::cout << std::endl;
}

void PacketParser::readBytes( char* mem, uint32_t bytes)
{
    byte_buffer.read(mem, bytes);
}

std::vector<ip_address> * PacketParser::getInclusions()
{
    return &include_ip;
}

std::vector<ip_address> * PacketParser::getExclusions()
{
    return &exclude_ip;
}

uint32_t PacketParser::getPacketCount( uint32_t protocol )
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

uint64_t PacketParser::getDataBytesCount( uint32_t protocol )
{
    return data_byte_counts[protocol];
}

uint64_t PacketParser::getPacketByteCount()
{
    return packet_bytes;
}
