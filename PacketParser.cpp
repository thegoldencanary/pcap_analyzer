#include "PacketParser.h"

PacketParser::PacketParser(pcap_t * file_handle)
    :file_handle( file_handle ),
    ip_filter_list( std::vector<short unsigned int>() )
{
}

int PacketParser::parsePackets( uint32_t number )
{
    // Setup our structs for holding header data
    const u_char *packet;
    struct pcap_pkthdr *header;
    for( int packets = 0; i < number; i++ )
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

void PacketParser::setIPFilter( short unsigned int ip )
{

}

void PacketParser::produceHistogram()
{

}

void PacketParser::produceBandwidths()
{

}

void PacketParser::readBytes( uint8_t* mem, uint32_t bytes)
{

}

std::vector<short unsigned int> * PacketParser::getFilterList()
{

}

uint32_t PacketParser::getTCPCount()
{

}

uint32_t PacketParser::getIPCount(){

}

uint32_t PacketParser::getEthCount(){

}

float PacketParser::getTimeElapsed(){

}

uint64_t PacketParser::getBytesRead(){

}

uint64_t PacketParser::getTCPBytesElapsed(){

}

