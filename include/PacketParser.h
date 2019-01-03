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

    void setIPFilter( short unsigned int ip );

    void produceHistogram();
    void produceBandwidths();
    void readBytes( uint8_t* mem, uint32_t bytes);
    int parsePackets( uint32_t number );

    // Getters
    std::vector<short unsigned int> * getFilterList();
    uint32_t getTCPCount();
    uint32_t getIPCount();
    uint32_t getEthCount();
    float getTimeElapsed();
    uint64_t getBytesRead();
    uint64_t getTCPBytesElapsed();

private:

    pcap_t* file_handle;

    std::vector<short unsigned int> ip_filter_list;
    uint32_t tcp_packets = 0;
    uint32_t ip_packets = 0;
    uint32_t eth_packets = 0;

    // TODO other packet counts

    float time_elapsed = 0;
    uint64_t bytes_elapsed = 0;
    uint64_t tcp_bytes_elapsed = 0;

};



