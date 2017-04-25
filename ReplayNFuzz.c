//http://www.microhowto.info/howto/send_an_arbitrary_ethernet_frame_using_libpcap.html
//Use LibPcap, exemple from site bellow
//gcc -Wall ReplayNFuzz.c -o ReplayNFuzz.out -lm -lpcap
#include <stdio.h>
#include <unistd.h>
#include <math.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <time.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>
#include "ReplayNFuzz.h"

short exec=1;

void usage(char *str, FILE *stream) {
    fprintf(stream,"%susage: ReplayNFuzz <-i> <-f> <-p [-p [-p […]]]> <-t>\n", str);
    fprintf(stream,"%7s-i <interface>\n", SEP);
    fprintf(stream,"%7s-f <pcap file>\n", SEP);
    fprintf(stream,"%7s-p <nbr packet>:<start offset b10>,<stop offset b10>\n", SEP);
    fprintf(stream,"%7s-t <time between pkts in ms>\n", SEP);
    fprintf(stream,"%7s |-> stop offset and start offset are fuzzed\n", SEP);
    fprintf(stream,"%7s |-> start offset is lower or equal to stop offset\n", SEP);
    fprintf(stream,"Exemple: \n");
    fprintf(stream," → Fuzze the first and the third packet of file \"mypcap.pcap\" at position \n   31-35 and 45, with interval of 10 ms on the second interface:\n");
    fprintf(stream,"%7s~$ ReplayNFuzz -i eth1 -f project/mypcap.pcap \\\n", SEP);
    fprintf(stream,"%7s               -p 0:30,34 -p 2:44,44 -t 10\n", SEP);
}

void  INThandler(int sig) {
    exec=0;
}

void save_context(char* filename, argp* ArgP){
    
    FILE *file = fopen(filename, "w");

    fprintf(file,"Params ---\n");
    fprintf(file, "if=%s time=%u file=%s\n", ArgP->inet, ArgP->time_wait, ArgP->pcap_name);
    fprintf(file, "ptr=");

    pFuzz* pos = ArgP->target;
    while (pos != NULL){
        fprintf(file,"{%u:%u,%u}", pos->pkt, pos->start.u, pos->stop.u);
        pos = pos->next;
    }
    fprintf(file,"\nData ---\n");

    pos = ArgP->target;
    u_char* ptr;

    while (pos!=NULL){
        fprintf(file,"%u|",pos->len);
        ptr = pos->start.ptr;

        while(ptr <= pos->stop.ptr){
            fprintf(file,"%c",*ptr);
            ptr++;
        }
        
        fprintf(file,"%c%c%c", 0x00, STOP_MARK, 0x00);
        pos = pos->next;
    }

    fclose(file);
}

int load_from_file (char* filename, argp* ArgP) {/*WIP*/
    FILE *file = fopen(filename, "r");
    char inet[10];
    char pcap_name[150];
    unsigned int time_wait, pkt, start, stop;

    if(file == NULL)
        return 1;
    fprintf(stderr,"1\n");

    fscanf(file,"Params ---\nif=%9s time=%u file=%149s\nptr=", inet, &time_wait, pcap_name);
    if(strcmp(inet, ArgP->inet) || strcmp(pcap_name,ArgP->pcap_name) || time_wait != ArgP->time_wait)
        return 2;
    fprintf(stderr,"2\n");

    pFuzz* pos = ArgP->target;
    while (pos!=NULL){
        fscanf(file,"{%u:%u,%u}", &pkt, &start, &stop);

        if(pos->pkt != pkt || pos->start.u != start || pos->stop.u != stop)
            return 3;

        pos = pos->next;
    }
    fprintf(stderr,"3\n");

    fscanf(file,"\nData ---\n");

    pos = ArgP->target;
    u_char* ptr;
    u_char val;
    unsigned int len;

    while (pos!=NULL){
        fscanf(file,"%u|", &len);
        
        if(len != pos->len)
            return 4;

        ptr = pos->start.ptr;
        
        while(ptr <= pos->stop.ptr){
            fscanf(file,"%c", &val);
            (*ptr)=val;
            ptr++;
        }

        fscanf(file,"%c%c%c", &val, &val, &val);
        pos = pos->next;
    }
    fprintf(stderr,"4\n");

    fclose(file);
    return 0;
}

int load_context (char* filename, argp* ArgP) {
    FILE *file = fopen(filename, "r");
    char inet[10];
    char pcap_name[150];
    unsigned int time_wait, pkt, start, stop;

    if(file == NULL)
        return 1;

    fscanf(file,"Params ---\nif=%9s time=%u file=%149s\nptr=", inet, &time_wait, pcap_name);
    if(strcmp(inet, ArgP->inet) || strcmp(pcap_name,ArgP->pcap_name) || time_wait != ArgP->time_wait)
        return 2;

    pFuzz* pos = ArgP->target;
    while (pos!=NULL){
        fscanf(file,"{%u:%u,%u}", &pkt, &start, &stop);

        if(pos->pkt != pkt || pos->start.u != start || pos->stop.u != stop)
            return 3;

        pos = pos->next;
    }

    fscanf(file,"\nData ---\n");

    pos = ArgP->target;
    u_char* ptr;
    u_char val;
    unsigned int len;

    while (pos!=NULL){
        fscanf(file,"%u|", &len);
        
        if(len != pos->len)
            return 4;

        ptr = pos->start.ptr;
        
        while(ptr <= pos->stop.ptr){
            fscanf(file,"%c", &val);
            (*ptr)=val;
            ptr++;
        }

        fscanf(file,"%c%c%c", &val, &val, &val);
        pos = pos->next;
    }

    fclose(file);
    return 0;
}

int inc(u_char * start, u_char* stop) {
    if (++(*start) == 0){
        if (start==stop) {
            return 0;
        }
        return inc(++start, stop);
    }
    return 1;
}

int dec(u_char * start, u_char* stop) {
    if (--(*start) == 0xFF){
        if (start==stop) {
            return 0;
        }
        return dec(start, --stop);
    }
    return 1;
}

unsigned long size_struct(unsigned long len) {
    unsigned long ret=0;
    while (len>0){
        ret+=pow(SIZE_STR,len);
        len--;
    }
    
    return ret;
}



int alea(u_char* start, u_char* stop) {
    while(start<=stop){
        (*start)= rand();
        start++;
    }
    return 0;
}

void init(u_char* start, u_char* stop){
    while(start<=stop){
        (*start)=0x00;
        start++;
    }
}

void p_init(pFuzz* pos){
    if(pos == NULL)
        return;
    init(pos->start.ptr, pos->stop.ptr);
    p_init(pos->next);
}

int p_ran (pFuzz* pos){
    while(pos != NULL){
        alea(pos->start.ptr, pos->stop.ptr);
        pos = pos->next;
    }
    return 1;
}

int p_ran_norep (pFuzz* pos){
    return 0;
}

int p_inc (pFuzz* pos){
    if(pos == NULL)
        return 0;
    if(!inc(pos->start.ptr, pos->stop.ptr)){
        init(pos->start.ptr, pos->stop.ptr);
        return p_inc(pos->next);
    }
    return 1;
}

int p_dos (pFuzz* pos){
    return 1;
}

int p_dec (pFuzz* pos){
    return 0;
}

char* readable_fs(double size/*in bytes*/, char *buf) {
    int i = 0;
    const char* units[] = {"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB"};
    while (size > 1024) {
        size /= 1024;
        i++;
    }
    sprintf(buf, "%.*f %s", i, size, units[i]);
    return buf;
}

int add_target(pFuzz** target, const char* params){
    struct _3ui ui_params={0,0,0,NULL,NULL};
    int ret = sscanf(params, "%u:%u,%u", &(ui_params.pkt), &(ui_params.start), &(ui_params.stop));
    if (ret != 3)
        return ret;
    if (ui_params.start > ui_params.stop)
        return -1;
    add_Ltarget(target, &ui_params);
    return ret;
}


void add_Ltarget(pFuzz** target, struct _3ui* params) {
    if ((*target)!=NULL && params->pkt >= (*target)->pkt){
        params->prev=(*target);
        add_Ltarget(&((*target)->next), params);
        return;
    }

    if ((*target)==NULL){ /*add at the end*/
        (*target) = malloc(sizeof(pFuzz));
        (*target)->next = NULL;
        
//        fprintf(stderr,"END  0x%X\n", *target);
    }
    else if (params->prev != NULL) { /*add in the middle*/
//        fprintf(stderr,"MIDDLE  IN 0x%X->0x%X->0x%X 0x%X->0x%X\n", params->prev, params->prev->next, params->prev->next->next, *target, (*target)->next);
        params->make = malloc(sizeof(pFuzz));
        params->make->next = params->prev->next;
        params->prev->next = params->make;
        
//        fprintf(stderr,"MIDDLE OUT 0x%X->0x%X->0x%X 0x%X->0x%X\n", params->prev, params->prev->next, params->prev->next->next, *target, (*target)->next);
    }
    else { /*add in first*/
//        fprintf(stderr,"FIRST  IN 0x%X->0x%X\n", *target, (*target)->next);
        params->prev = malloc(sizeof(pFuzz));
        params->prev->next = (*target);
        (*target) = params->prev;
        
//        fprintf(stderr,"FIRST OUT 0x%X->0x%X\n", *target, (*target)->next);
    }
    
    init_target(*target, params);

    return;
}

static inline void init_target(pFuzz* target, struct _3ui* params) {
    target->start.u =  params->start;
    target->stop.u  =  params->stop;
    target->pkt     =  params->pkt;
    target->len     = (params->stop - params->start) + 1;
}

void print_pFuzz(FILE *stream, pFuzz *target) {
    if(target==NULL) return;
    fprintf(stream,"%7u %u %u (%u byte(s))\n",target->pkt, target->start.u,
            target->stop.u, target->len);
    print_pFuzz(stream, target->next);
    return;
}

unsigned int all_len(pFuzz *target) {
    if(target==NULL) return 0;
    return target->len + all_len(target->next);
}

process get_process(argp* ArgP) {
    unsigned int len = all_len(ArgP->target);
    if (len > LEN_MAX_INC)
        return p_ran;
    if (len == 0)
        return p_dos;
    return p_inc;
}

void print_args(FILE *stream, argp* ArgP) {
    fprintf(stream,"%7s %u ms\n",ArgP->inet, (ArgP->time_wait)/1000);
    print_pFuzz(stream, ArgP->target);
    return;
}

int itoptr(argp* ArgP){
    lframe *ptr_fr = ArgP->frames;
    pFuzz *ptr_pos = ArgP->target;
    unsigned int pkt = 0;

    while(ptr_pos != NULL){
        if(ptr_fr == NULL) return 0;
        if(ptr_pos->pkt != pkt){
            ptr_fr = ptr_fr->next;
            pkt++;
        }
        else{
            if(ptr_pos->stop.u >= ptr_fr->length) return 0;
            ptr_pos->start.ptr = ptr_pos->start.u + ptr_fr->frame;
            ptr_pos->stop.ptr  = ptr_pos->stop.u  + ptr_fr->frame;
            ptr_pos = ptr_pos->next;
        }
    }
        
    return 1;
}

int init_frame(argp* ArgP, pcap_t* cap_ptr){
    struct pcap_pkthdr header;
    lframe* ptr_frame;
    const u_char* packet;

    packet = pcap_next(cap_ptr, &header);
    
    if(packet == NULL)
        return 0;

    ArgP->frames = malloc(sizeof(lframe));
    ArgP->frames->length = header.len;
    ArgP->frames->frame = malloc(sizeof(u_char)*header.len);
    memcpy(ArgP->frames->frame,packet,sizeof(u_char)*header.len);

    ptr_frame=ArgP->frames;
    fprintf(stderr, "1rst\n%7u 0x%X 0x%X\n",ArgP->frames->length, ArgP->frames->frame[header.len-1], packet[header.len-1]);

        packet = pcap_next(cap_ptr, &header);
    while(packet != NULL){
        ptr_frame->next = malloc(sizeof(lframe));
        ptr_frame = ptr_frame->next;
        ptr_frame->length = header.len;
        ptr_frame->frame = malloc(sizeof(u_char)*header.len);
        memcpy(ptr_frame->frame,packet,sizeof(u_char)*header.len);
//        fprintf(stderr, "New -\n%7u 0x%X 0x%X\n",ptr_frame->length, ptr_frame->frame[header.len-1], packet[header.len-1]);
        packet = pcap_next(cap_ptr, &header);
    }

    ptr_frame->next = NULL;

    return 1;
}

int parse_arg(argp* ArgP, int argc, const  char* argv[]) {
    int c;
    char errbuf[PCAP_ERRBUF_SIZE];

    while ((c = getopt (argc, argv, "i:f:p:t:")) != -1) {
        switch (c) {
            case 'f':
                if (ArgP->frames != NULL){
                    error("pcap file already defined");
                    exit(1);
                }
                pcap_t* cap_ptr = pcap_open_offline(optarg, errbuf);
                ArgP->pcap_name = optarg; /*save purpose*/
                if (cap_ptr == NULL) {
                    fprintf(stderr, "error reading pcap file: %s\n", errbuf);
                    error("incorrect arguments\n");
                    exit(1);
                }
                if (!init_frame(ArgP, cap_ptr)){
                    error("error on pcap frame reading\n");
                    exit(1);
                }
                pcap_close(cap_ptr);
                break;
            case 'p':
                if (add_target(&(ArgP->target), optarg) != 3) {
                    error("incorrect frame number or incorrect fuzzing position\n");
                    exit(2);
                }
                break;
            case 't':
                if (ArgP->time_wait != 0){
                    error("time already defined");
                    exit(3);
                }
                ArgP->time_wait=strtoul(optarg,NULL,10)*1000;
                break;
            case 'i':
                if (ArgP->inet != NULL){
                    error("inet interface already defined");
                    exit(4);
                }
                ArgP->inet=optarg;
                break;
            case '?':
                info();
                return 1;
            default:
                error("incorrect arguments!\n");
                exit(5);
                break;
        }
    }
    if ( ArgP->frames == NULL ){
        error("no pcap defined\n");
        exit(6);
    }
    if ( ArgP->target == NULL) {
        fprintf(stdout,"no position defined: DoS mode\n");
    }
    if ( ArgP->inet == NULL) {
        error("no interface defined\n");
        exit(8);
    }
    print_args(stdout, ArgP);
    if(!itoptr(ArgP)){
        error("inconsistent position: 'p' flag(s) not valid with this pcap file.\n");
        exit(9);
    }

    return 1;
}



int main(int argc,const char* argv[]) {
    // Get command line argument
    argp ArgP={NULL, NULL, 0, NULL};
    if(!parse_arg(&ArgP, argc, argv))
        return 1;

    // Open a PCAP packet capture descriptor for the specified interface.
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    pcap_errbuf[0]='\0';
    pcap_t* pcap=pcap_open_live(ArgP.inet,96,0,0,pcap_errbuf);
    if (pcap_errbuf[0]!='\0') {
        fprintf(stderr,"%s\n",pcap_errbuf);
    }
    if (!pcap)
        exit(1);
    
 
    //reload preview session
    int ret=load_context(SAVE_FILE, &ArgP);
    if (!ret) {
        fprintf(stdout,"restart Fuzzing\n");
    }
    else {
        fprintf(stdout,"[%i] start job!\n", ret);
    }

    //function ptr
    process ps = get_process(&ArgP);

    if (ps == p_inc){
        if(ret)
            p_init(ArgP.target);/*start from 0x00*/
        fprintf(stdout, "INCREMENTAL\n");
    }
    else if (ps == p_ran) {
        srand((unsigned int) time(NULL));/*init rand function*/
        fprintf(stdout,"RANDOM\n");
    }

    //Flush stdout before processing
    fflush(stdout);
    
    //install Handler to save session
    signal(SIGINT, INThandler);

    lframe* ptr_frame;
    do{ /*First time, replay with current status…*/
        // Write Ethernet frame to the interface
        ptr_frame = ArgP.frames;
        while (ptr_frame != NULL){
            if (pcap_inject(pcap,ptr_frame->frame,sizeof(u_char)*(ptr_frame->length))==-1) {
                pcap_perror(pcap,0);
                pcap_close(pcap);
                exit(1);
            }
            usleep(ArgP.time_wait);
            ptr_frame = ptr_frame->next;
        }
    }while ((*ps)(ArgP.target) && exec);

    if (!exec) {
        fprintf(stderr,"Save and exit!\n");
        save_context(SAVE_FILE, &ArgP);
    }

    // Close the PCAP descriptor.
    pcap_close(pcap);

    return 0;
}

