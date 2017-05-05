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
//#include <poll.h>
#include "ReplayNFuzz.h"

short exec=1;
pcap_t* handle_cap;

void usage(char *str, FILE *stream) {
    fprintf(stream,"%susage: ReplayNFuzz <-i> <-f> <-p [-p [-p […]]]> <-t> [-c]\n", str);
    fprintf(stream,"%7s-i <interface>\n", SEP);
    fprintf(stream,"%7s-f <pcap file>\n", SEP);
    fprintf(stream,"%7s-c <pcap file: check target>,<\"my filter\" (pcap form)>\n", SEP);
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

void alarm_handler(int sig) {
    pcap_breakloop(handle_cap);
    exec=-1;
}

void pFuzz_close(pFuzz* pfz){
/*TODO*/
}

void lframe_close (lframe* lfr){
/*TODO*/
}

void chkta_close (chkta* ck) {
    if (ck->PcapP != NULL){/*DO NOT free pcap object*/
        pcap_close(ck->PcapP->pcap_out);
        free(ck->PcapP);
        ck->PcapP = NULL;
    }
    lframe_close(ck->frames);
    
    /*TODO*/
}

void argp_close(argp* ArgP){
    if (ArgP->chk_ta != NULL){
        chkta_close(ArgP->chk_ta);
        free(ArgP->chk_ta);
        ArgP->chk_ta = NULL;
    }
    
    lframe_close(ArgP->frames);
    pFuzz_close(ArgP->target);
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

int ck_null (argp* ArgP) {
    return 0;
}

int init_pcap_ck (argp* ArgP){
    chkta* chk = ArgP->chk_ta;
    
    chk->PcapP = malloc(sizeof(pcap_prop));
    pcap_prop* mycap = chk->PcapP;

    mycap->pcap_errbuf[0]='\0';
    mycap->pcap_out=pcap_open_live(ArgP->inet,96,1,250,mycap->pcap_errbuf);
    if(pcap_lookupnet(ArgP->inet, &(mycap->net), &(mycap->mask), mycap->pcap_errbuf) == -1){
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", ArgP->inet, mycap->pcap_errbuf);
        mycap->net=0;
        mycap->mask=0;
    }
    if (mycap->pcap_errbuf[0]!='\0') {
        fprintf(stderr,"%s\n",mycap->pcap_errbuf);
    }
    if (!mycap->pcap_out)
        return 1;
    if (pcap_compile(mycap->pcap_out,&(mycap->fp),chk->filter,0,mycap->net)== -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", chk->filter, pcap_geterr(mycap->pcap_out));
        return 2;
    }
    if (pcap_setfilter(mycap->pcap_out,&(mycap->fp))==-1){
        fprintf(stderr, "Couldn't install filter %s: %s\n", chk->filter, pcap_geterr(mycap->pcap_out));
        return 3;
    }


    /*timeout for packet listen*/
    handle_cap = mycap->pcap_out;

    /*prepare poll: validate medium acess*/
//    mycap-> fd = pcap_get_selectable_fd(mycap->pcap_out);
//    if (mycap->fd != -1) {
//        mycap->pfd.fd      = mycap->fd;
//        mycap->pfd.events  = 0;
//        mycap->pfd.revents = 0;
        //poll(&(mycap->pfd),1,100);
//        fprintf(stdout, "Init poll trigger %i\n", mycap->fd);
//    }
//    else {
//        fprintf(stderr, "Can't init poll /!\\");
//    }
    
    return 0;
}

int ck_icmp (argp* ArgP) {
    lframe* ptr_frame  = ArgP->chk_ta->frames;
    pcap_prop* ptr_cap = ArgP->chk_ta->PcapP;
    int ret = 1;

    while (ptr_frame != NULL){
        if (pcap_inject(ptr_cap->pcap_out,ptr_frame->frame,sizeof(u_char)*(ptr_frame->length))==-1) {
            pcap_perror(ptr_cap->pcap_out,0);
            return 1;
        }

//        poll(&(ptr_cap->pfd),0,10);
        alarm(3);
        signal(SIGALRM, alarm_handler);
        ret = pcap_next_ex(ptr_cap->pcap_out,&(ptr_cap->header), &(ptr_cap->packet));
        usleep(ArgP->time_wait);
        ptr_frame = ptr_frame->next;

        if ( !ret || (exec == -1) ){
            return 0;
        }
	/*Other check on the frame*/
    }
    return ret;
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

int add_ck_target(chkta** chk, const char* params){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* cap_ptr;
    char *f_pcap = NULL, *str = NULL;
    unsigned int len = strlen(params);
    unsigned int pos = 0;

    /*split*/ 
    f_pcap = (char *) malloc(len);

    for (pos=0; params[pos] != ',' && pos < len; pos++)
        f_pcap[pos]=params[pos];
    
    f_pcap[pos]=0; str = f_pcap + (++pos);

    if (pos < len) {
        while (params[pos])
            f_pcap[pos]=params[pos++];
    
        f_pcap[pos]=0;
    }

    /*init object*/ 
    if ((*chk) != NULL){
        error("pcap for checking purpose aleady defined");
        exit(-1);
    }

    (*chk) = malloc(sizeof(chkta));
    cap_ptr = pcap_open_offline(f_pcap, errbuf);

    (*chk)->pcap_name = f_pcap; /*save purpose*/
    (*chk)->filter = str;

    if (cap_ptr == NULL) {
        fprintf(stderr, "error reading pcap file: %s\n", errbuf);
        error("incorrect arguments\n");
        exit(-1);
    }
    if (!init_frame(&((*chk)->frames), cap_ptr)){
        error("error on pcap frame reading\n");
        exit(-1);
    }
    (*chk)->PcapP = NULL;
    pcap_close(cap_ptr);
    (*chk)->filter = str;
    return 0;
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

check get_check(argp* ArgP) {
    if (ArgP->chk_ta == NULL)
        return ck_null;
    init_pcap_ck(ArgP);
    return ck_icmp;
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

void print_frame(char* str, lframe* frames) {

    fprintf(stdout,str);
    for(int i=0;i<=frames->length;i++){
        
        if (i%16 == 0)
            fprintf(stdout,"\n");

        fprintf(stdout,"%02x ",frames->frame[i]);
    }
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

/*TODO*/
//void custom_frame_addr(lframe * frames, u_int8_t mac_src, u_int8_t mac_dst){/*cutom MAC and IP addr*/
//    ether_header* ether=frames->frame;
//
//    ether->ether_dhost = mac_dst;/*repositionner les octets avce la méthode qui va bien
//    ether->ether_shost = mac_src;
//
//    if (ether->ether_type == ETHERTYPE_IP){
//        iphdr* ip=frames->frame[sizeof(ether_header)];
//    }
//     
//}

int init_frame(lframe** p_frames, pcap_t* cap_ptr){
    struct pcap_pkthdr header;
    lframe* ptr_frame;
    const u_char* packet;

    packet = pcap_next(cap_ptr, &header);
    
    if(packet == NULL)
        return 0;

    (*p_frames) = malloc(sizeof(lframe)); 
    (*p_frames)->length = header.len;
    (*p_frames)->frame = malloc(sizeof(u_char)*header.len);
    memcpy((*p_frames)->frame,packet,sizeof(u_char)*header.len);

    ptr_frame=(*p_frames);
    fprintf(stderr, "1rst\n%7u 0x%X 0x%X\n",(*p_frames)->length, (*p_frames)->frame[header.len-1], packet[header.len-1]);

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
    pcap_t* cap_ptr;

    while ((c = getopt (argc, argv, "i:f:p:t:c:")) != -1) {
        switch (c) {
            case 'f':
                if (ArgP->frames != NULL){
                    error("pcap file already defined");
                    exit(1);
                }
                cap_ptr = pcap_open_offline(optarg, errbuf);
                ArgP->pcap_name = optarg; /*save purpose*/
                if (cap_ptr == NULL) {
                    fprintf(stderr, "error reading pcap file: %s\n", errbuf);
                    error("incorrect arguments\n");
                    exit(1);
                }
                if (!init_frame(&(ArgP->frames), cap_ptr)){
                    error("error on pcap frame reading\n");
                    exit(1);
                }
                pcap_close(cap_ptr);
                break;
            case 'c':
                if (add_ck_target(&(ArgP->chk_ta), optarg)) {
                    error("incorrect \"check target\" parmeters\n");
                    exit(6);
                }
                fprintf(stdout, "  pcap=%s\n  filter=%s\n", ArgP->chk_ta->pcap_name, ArgP->chk_ta->filter);
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
    argp ArgP={NULL, NULL, 0, NULL, NULL};
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
    check chk = get_check(&ArgP);

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
            if (!(*chk)(&ArgP)){ /*Validate target alive*/
                fprintf(stdout, "No response from target in %u ms\n",ArgP.time_wait);
                print_frame("Check:",ArgP.chk_ta->frames);
                print_frame("\nFuzz:",ptr_frame);
                exec=0;
                break;
            }
            ptr_frame = ptr_frame->next;

        }
    }while ((*ps)(ArgP.target) && exec); /*Fuzz (or custom) frames*/

    if (!exec) {
        fprintf(stdout,"\nSave and exit!\n");
        save_context(SAVE_FILE, &ArgP);
    }

    // Close the PCAP descriptor.
    pcap_close(pcap);
    argp_close(&ArgP);
    return 0;
}

