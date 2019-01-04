#include <algorithm>

#include "PacketParser.h"

PacketParser::PacketParser(pcap_t * file_handle)
    :file_handle( file_handle ),
    ip_filter_list( std::vector<in_addr>() )
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
        const struct tcphdr *tcp_hdr;

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
            for( auto x : ip_filter_list )
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

                tcp_packets += 1;
                bytes_elapsed += sizeof( tcp_hdr );
                eth_packets += 1;
                bytes_elapsed += sizeof( eth_hdr );
                ip_packets += 1;
                bytes_elapsed += sizeof( ip_hdr );
                bytes_elapsed += length;
                tcp_bytes_elapsed += length;
                packet_bytes += header->len;
                packet_time = header->ts.tv_sec * 1000000 + header->ts.tv_usec;
                if( current_time == 0 )
                {
                    current_time = packet_time;
                }
                time_elapsed += packet_time - current_time;
                current_time = packet_time;
            }
            else
            {
                // Unsupported protocol, will return
                return -1;
            }
        }else
        {
            // Unsupported ethertype, will return
            return -1;
        }
    }

    return 0;
}

void PacketParser::setIPFilter( in_addr ip )
{
    ip_filter_list.push_back(ip);
}

void PacketParser::produceHistogram()
{

}

void PacketParser::produceBandwidths()
{
    uint32_t bandwidth = tcp_bytes_elapsed /
                         ( time_elapsed / 1000000 );
    std::cout << "Bandwidth: " << bandwidth << " bytes/s" << std::endl;
}

void PacketParser::readBytes( uint8_t* mem, uint32_t bytes)
{

}

std::vector<in_addr> * PacketParser::getFilterList()
{
    return &ip_filter_list;
}

uint32_t PacketParser::getTCPCount()
{
    return tcp_packets;
}

uint32_t PacketParser::getIPCount()
{
    return ip_packets;
}

uint32_t PacketParser::getEthCount()
{
    return eth_packets;
}

uint64_t PacketParser::getTimeElapsed()
{
    return time_elapsed;
}

uint64_t PacketParser::getBytesRead()
{
    return bytes_elapsed;
}

uint64_t PacketParser::getTCPBytesRead()
{
    return tcp_bytes_elapsed;
}

uint64_t PacketParser::getPacketByteCount()
{
    return packet_bytes;
}
