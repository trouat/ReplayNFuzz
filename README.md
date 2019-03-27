# ReplayNFuzz
`gcc -Wall ReplayNFuzz.c -o ReplayNFuzz.out -lm -lpcap`

    usage: ReplayNFuzz <-i> <-f> <-p [-p [-p […]]]> <-t> [-c]
           -i <interface>
           -f <pcap file>
           -c <pcap file: check target>,<"my filter" (pcap form)>
           -p <nbr packet>:<start offset b10>,<stop offset b10>
           -t <time between pkts in ms>
            |-> stop offset and start offset are fuzzed
            |-> start offset is lower or equal to stop offset
    Exemple: 
     → Fuzze the first and the third packet of file "mypcap.pcap" at position 
       31-35 and 45, with interval of 10 ms on the second interface:
           ~$ ReplayNFuzz -i eth1 -f project/mypcap.pcap \
                          -p 0:30,34 -p 2:44,44 -t 10
