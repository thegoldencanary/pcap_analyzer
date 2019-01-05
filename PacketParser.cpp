#include <algorithm>

#include "PacketParser.h"

PacketParser::PacketParser(pcap_t * file_handle)
    :file_handle( file_handle ),
    exclude_ip( std::vector<in_addr>() ),
    include_ip( std::vector<in_addr>() )
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
        const struct ip *ip_hdr;

        // Get the inital ethernet header
        eth_hdr = ( struct ether_header* ) packet;

        // Check the type of payload
        // If IP
        if( ntohs( eth_hdr->ether_type ) == ETHERTYPE_IP )
        {
            // Get IP header
            ip_hdr = ( struct ip* )( packet + sizeof(struct ether_header ) );
            in_addr dest_address = ip_hdr->ip_dst;
            in_addr src_address = ip_hdr->ip_src;
            bool filter = false;
            for( auto x : exclude_ip )
            {
                if( x.s_addr == dest_address.s_addr )
                {
                    filter = true;
                    break;
                }
            }
            if( filter )
            {
                continue;
            }
            if( !include_ip.empty() )
            {
                filter = true;
                for( auto x : include_ip )
                {
                    if( x.s_addr == dest_address.s_addr )
                    {
                        filter = false;
                        break;
                    }
                }
            }
            if( filter )
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

            packet_counts[ETHERNET] += 1;
            packet_counts[PROTOCOL_IP] += 1;
            bytes_elapsed += sizeof( ip_hdr );
            bytes_elapsed += sizeof( eth_hdr );
            packet_bytes += header->len;
            packet_time = header->ts.tv_sec * 1000000 + header->ts.tv_usec;
            if( current_time == 0 )
            {
                current_time = packet_time;
            }
            time_elapsed += packet_time - current_time;
            current_time = packet_time;

        }else
        {
            // Unsupported ethertype, will return
            return -1;
        }
    }

    return 0;
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

void PacketParser::setExclusions( std::vector<in_addr> ip )
{
    exclude_ip = ip;
}

void PacketParser::setInclusions( std::vector<in_addr> ip )
{
    include_ip = ip;
}

void PacketParser::produceHistogram( uint32_t protocol, uint64_t bin_width )
{
    if( protocol == IPPROTO_TCP )
    {

    }
}

void PacketParser::produceBandwidths( uint32_t protocol )
{
    uint32_t bandwidth = data_byte_counts[protocol] /
                         ( time_elapsed / 1000000 );
    std::cout << "Bandwidth: " << bandwidth << " bytes/s" << std::endl;
    std::cout << std::endl;
}

void PacketParser::readBytes( char* mem, uint32_t bytes)
{
    byte_buffer.read(mem, bytes);
}

std::vector<in_addr> * PacketParser::getInclusions()
{
    return &include_ip;
}

std::vector<in_addr> * PacketParser::getExclusions()
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
