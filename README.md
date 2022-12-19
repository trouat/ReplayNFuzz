# Introduction
Ce code est un utilitaire permettant de rejouer des trames Ethernet contenues dans un fichier PCAP ou capturées sur une interface réseau. Il permet également de faire du « fuzzing » sur certaines parties de ces trames, c'est-à-dire de les modifier de manière aléatoire pour tester la robustesse d'un système ou d'un protocole en réseau.

Le programme peut être exécuté avec divers arguments en ligne de commande pour spécifier l'interface réseau à utiliser, le fichier PCAP à utiliser, les trames à modifier et le délai entre chaque trame envoyée. Des exemples d'utilisation sont donnés dans l'aide en ligne de la commande.

# Compilation
`gcc -Wall ReplayNFuzz.c -o ReplayNFuzz.out -lm -lpcap`

# Utilisation
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
