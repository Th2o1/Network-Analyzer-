#include <stdio.h>
#include <pcap.h>
#include <unistd.h>
#include <stdlib.h>
// i ou bien o
// f optio
// v pas obliger pas defaut
void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet){
    printf("Paquet capturé de longueur %d octets\n", pkthdr->len);
}


int main(int argc, char *argv[]){
    char errbuf[PCAP_ERRBUF_SIZE];
    char *interface, *file = NULL;
    printf("%s, %s", interface, file);
    int verbosity=1;
    int opt;
    while ((opt = getopt(argc, argv, "i:o:f:v:")) != -1) {
    //Gestion des options de la commande 
    // -i <interface> : interface pour l’analyse live
    // -o <fichier> : fichier d’entrée pour l’analyse offline
    // -f <filtre> : filtre BPF (optionnel)
    // -v <1..3> : niveau de verbosité (1=très concis ; 2=synthétique ; 3=complet)
        switch (opt) {
            case 'i':
                interface = optarg;
                break;
            case 'o':
                file = optarg;
                break;
            case 'f':
                break;
            case 'v':
                verbosity = atoi(optarg);
                break;
            case '?':
                fprintf(stderr, "Usage: %s [-i interface] [-o file] [-f filter] [-v 1..3]\n", argv[0]);
                return 1;
        }
    }
    if(interface != NULL){

    }
    pcap_if_t *alldevs;
    
    // Récupérer la liste de toutes les interfaces
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Erreur lors de la récupération des interfaces: %s\n", errbuf);
        return 1;
    }

    // pcap_if_t *device;
    // printf("Interfaces disponibles :\n");
    // for (device = alldevs; device != NULL; device = device->next) {
    //     printf("%s", device->name);  
    // }

    const char* device = alldevs->name;
    pcap_t* capture_session = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf); 

    if (capture_session == NULL){
        fprintf(stderr, "Erreur lors de la capture de tram: %s\n", errbuf);
        return 1;
    }

    if(pcap_loop(capture_session, 10, packet_handler, NULL) < 0){
        fprintf(stderr, "error");
    }
    

    pcap_freealldevs(alldevs);
    pcap_close(capture_session);
    return 0;
}