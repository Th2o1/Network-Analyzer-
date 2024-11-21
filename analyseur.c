#include "analyseur.h"

// i ou bien o
// f optio
// v pas obliger pas defaut

void packet_handler(u_char *verbosity, const struct pcap_pkthdr *pkthdr, const u_char *packet){
    int *verb = (int *)verbosity;
    parse_packet(packet, verb);
}

int main(int argc, char *argv[]){
    char errbuf[PCAP_ERRBUF_SIZE];
    char *interface, *file = NULL;
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
    if((interface == NULL && file == NULL) || (interface != NULL && file != NULL) ){
        fprintf(stderr, "You need at least an interface or a file, but not both\n");
        fprintf(stderr, "Usage: %s [-i interface] [-o file]\n", argv[0]);
    }

    pcap_t* capture_session;
    if(interface != NULL){
        capture_session = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf); 
        if (capture_session == NULL){
            fprintf(stderr, "Error while capturing: %s\n", errbuf);
            pcap_if_t *alldevs;
            // Récupérer la liste de toutes les interfaces
            if (pcap_findalldevs(&alldevs, errbuf) == 0) {
                pcap_if_t *device;
                printf("Usable interface :\n");
                for (device = alldevs; device != NULL; device = device->next) {
                    printf("- %s\n", device->name);  
                }
            }
            pcap_freealldevs(alldevs);
            return 1;
        }
    }
    else{
        capture_session = pcap_open_offline(file, errbuf);
        if(capture_session == NULL){
            fprintf(stderr, "Error: file not found\n");
            return 1;
        }
    }
    //mettre à 0 à la place de 10 pour capture 'infini'
    if(pcap_loop(capture_session, 0, packet_handler, (u_char *)&verbosity) < 0){
        fprintf(stderr, "Error while calling loop \n");
    }
    pcap_close(capture_session);
    return 0;
}