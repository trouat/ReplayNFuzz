#ifndef __ReplayNFuzz_HEADER
#define __ReplayNFuzz_HEADER
#define SAVE_FILE ".ReplayNFuzz_context"
#define error(string) usage(string, stderr)
#define info() usage("",stdout)
#define SIZE_STR    32
#define SEP         ""
#define LEN_MAX_INC 4
#define STOP_MARK   129


struct u_ptr {/*if save purpose aren't used, modify to 'union'*/
    u_char* ptr;
    unsigned int u;/*used for initialization*/
};

typedef struct PcapProperties {
    pcap_t* pcap_out;
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 net;
    bpf_u_int32 mask;
//    char* filter; /*Static: LIBPCAP_FILTER*/
    struct pcap_pkthdr* header;
    const u_char *packet;
    struct bpf_program fp;
 //   int fd;
//    struct pollfd pfd;
} pcap_prop;

typedef struct LinkedFrame {
    u_char* frame;
    unsigned int length;
    struct LinkedFrame* next;
} lframe;

typedef struct PosFuzz {
    unsigned int pkt; /*Packet number in frames*/
    struct u_ptr start; /*Start ptr in packet*/
    struct u_ptr stop; /*Stop ptr in packet*/
    unsigned int len;
    struct PosFuzz* next; /*Next fuzzing session*/
} pFuzz;

typedef struct TargetAlive {
    lframe* frames; /*Frames of test*/
    char* pcap_name; /*PCAP name*/
    pcap_prop *PcapP; /*pcap inject parameters*/
    char* filter;/*ptr to filter parameter*/
} chkta;

typedef struct ArgParse {
    lframe* frames;
    pFuzz* target;
    useconds_t time_wait;
    char *inet, *pcap_name;
    chkta* chk_ta;
} argp;

struct _3ui {
    unsigned int pkt, start, stop;
    pFuzz *prev;
    pFuzz *make;
};

typedef int (*process) (pFuzz*);
typedef int (*check) (argp*);

void usage(char *str, FILE *stream);

void INThandler(int sig);

void save_context(char* filename, argp* ArgP);
int  load_context(char* filename, argp* ArgP);
//void save_all(char* name_of_file, int argc, const char* argv[], char* start, char* stop);
//int load_all (char* name_of_file, int argc, const char* argv[], char* start, char* stop);

int  inc (u_char* start, u_char* stop);
int  dec (u_char* start, u_char* stop);
int  alea(u_char* start, u_char* stop);
void init(u_char* start, u_char* stop);

int init_pcap_ck(argp* ArgP);

int p_inc(pFuzz* target);/*comprehensive fuzzing, incremental*/
int p_dec(pFuzz* target);/*comprehensive fuzzing, decremental*/
int p_ran(pFuzz* target);/*random sampling with replacement*/
int p_ran_norep(pFuzz* target);/*random sampling without replacement*/

int ck_null(argp* ArgP);/*no check*/
int ck_icmp(argp* ArgP);/*icmp check*/

unsigned long size_struct(unsigned long len);

char* readable_fs(double size/*in bytes*/, char *buf);

int add_target(pFuzz** target, const char* params);
void add_Ltarget(pFuzz** target, struct _3ui* params);
//inline void init_target(pFuzz* target, struct _3ui* params);
static inline void init_target(pFuzz* target, struct _3ui* params);
int init_frame(lframe** p_frames, pcap_t* cap_ptr);
int itoptr(argp* ArgP);
//inline void ptrtoi(argp* ArgP);

unsigned int all_len(pFuzz* target);

void print_pFuzz(FILE *stream, pFuzz *target);
void print_args(FILE *stream, argp* ArgP);

int parse_arg(argp* ArgP, int argc, const char* argv[]);

process get_process(argp* ArgP);

check get_check(argp* ArgP);

#endif
