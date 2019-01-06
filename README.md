# pcap_analyzer
An packet analysis tool using pcap

[Prerequisites]
Requires the libpcap library (https://www.tcpdump.org/)

[Build]
mkdir build
cd build
cmake ..
make

[Run]
./build/pcap [args]

     -f, --filename       Select file for input 
     -h, --histogram      Prints a histogram of 
                          the given protocol 
     -b, --byte-stream    Outputs to standard out the 
                          TCP byte stream 
     -i, --include-ip     Parses only the ip(s) given 
     -x, --exclude-ip     Ignores the ip(s) given 
     -s, --statistics     Prints to output statistics 
                          of the packets in the file 
     -t, --throughput     Prints the throughput in bytes/s
                          of the given protocol datastream 
     --filter-dest        Filters IPs by destination only 
     --filter-src         Filters IPs by source only 
     --bin-width          Set histogram bin width in ms
     --help               Prints this help menu 
                          
     For filtering multiple IP addresses, wrap space 
     seperated in "" ("192.168.0.1 192.168.1.1") 
     You may use only one type of filter at a time 
     
     Viable protocols are: 
     tcp udp eth ip ip6
     
     Only TCP carries actual data and the bandwidth
     reflects that ( other protocols will show 0 )
    
[Implementation]

I have implemented some statistics gathering on packet counts
and byte counts, bytes/s for TCP data, histogram for packet counts
over time, IP filters, and raw TCP data stream output.

The Parser class contains methods for running over the file
and parsing individual packets. It updates various statistics
as it goes, and can calculate/output relevant data at any point.
It can be expanded by checking for new protocols in headers and
adding new methods to parse each protocol in turn.

The command line tool allows for various outputs and you can
filter individual IPs as you see fit.

