#include "analyseur.h"

// tcpdump -r data/smtp.pcap -n -vv
// i ou bien o
// f optio
// v pas obliger pas defaut

int verbosity = 0;
size_t packet_size = 0;
// Capture session
pcap_t* capture_session;
// Filter
struct bpf_program fp;
// Current packet number 
int packet_number = 0;
// To know the packet number (debigging)
void print_packet_number(){
    packet_number++;
    printf("Packet captured : %d\n", packet_number);
}

void handle_sigint(int sig) {
    (void)(sig);
    printf("\nCleaning up before exiting...\n\n");
    
    pcap_close(capture_session);
    pcap_freecode(&fp);
    printf("Packet %d\n", packet_number);
    exit(0); // Exit the program
}


void packet_handler(u_char *verbos, const struct pcap_pkthdr *pkthdr, const u_char *packet){
    (void)(verbos); // unused error 
    packet_size = pkthdr->len; // Total size of the packet put in global value
    print_packet_number();
    parse_packet(packet);
    print_packet(packet, packet_size); //Print raw packet (usefull for debuging)
}

int main(int argc, char *argv[]){

    char errbuf[PCAP_ERRBUF_SIZE];
    memset(errbuf, 0, PCAP_ERRBUF_SIZE);
    char *interface = NULL , *file = NULL;
    const char* bpf_filter = NULL;
    verbosity = 1;

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
                bpf_filter = optarg;
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
        return 1;
    }

    
    signal(SIGINT, handle_sigint);
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
            fprintf(stderr, "Error: %s with file %s \n", file, errbuf);
            return 1;
        }
    }

    // Apply filter if needed
    if (bpf_filter != NULL) {
        if (pcap_compile(capture_session, &fp, bpf_filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
            fprintf(stderr, "Error compiling BPF filter: %s\n", pcap_geterr(capture_session));
            pcap_close(capture_session);
            return 1;
        }
        if (pcap_setfilter(capture_session, &fp) == -1) {
            fprintf(stderr, "Error setting BPF filter: %s\n", pcap_geterr(capture_session));
            pcap_freecode(&fp);
            pcap_close(capture_session);
            return 1;
        }
        pcap_freecode(&fp); // Libérer la mémoire allouée pour le filtre compilé
    }

    // Start the loop 
    if(pcap_loop(capture_session, 0, packet_handler, (u_char *)&verbosity) < 0){
        fprintf(stderr, "Error while calling loop \n");
        pcap_close(capture_session);
        pcap_freecode(&fp);
    }
    pcap_close(capture_session);
    pcap_freecode(&fp);
    return 0;
}