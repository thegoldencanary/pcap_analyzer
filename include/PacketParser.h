#pragma once

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

class PacketParser
{

public:

    PacketParser(pcap_t *file_handle);

    void setIPFilter( in_addr ip );

    void produceHistogram();
    void produceBandwidths();
    void readBytes( uint8_t* mem, uint32_t bytes);
    int parsePackets( uint32_t number );

    // Getters
    std::vector<in_addr> * getFilterList();
    uint32_t getTCPCount();
    uint32_t getIPCount();
    uint32_t getEthCount();
    uint64_t getTimeElapsed();
    uint64_t getBytesRead();
    uint64_t getTCPBytesRead();
    uint64_t getPacketByteCount();

private:

    pcap_t* file_handle;

    std::vector<in_addr> ip_filter_list;
    uint32_t tcp_packets = 0;
    uint32_t ip_packets = 0;
    uint32_t eth_packets = 0;

    // TODO other packet counts

    uint64_t time_elapsed = 0;
    uint64_t bytes_elapsed = 0;
    uint64_t tcp_bytes_elapsed = 0;
    uint64_t current_time = 0;
    uint64_t packet_time = 0;

    uint64_t packet_bytes = 0;

};



