/*
  g++ t.cpp -I/usr/include/glib-2.0 -I/usr/lib/glib-2.0/include -I. -I../include/ -lpthread -L/home/santosh/proj -lpcap -L/home/santosh/proj  -lwireshark
 */

#include <wireshark/config.h> /* needed by epan */

#include <epan/epan.h>
#include <epan/prefs.h>
#include <epan/timestamp.h>
#include <epan/print.h>
#include <wsutil/privileges.h>
#include <wsutil/report_err.h>
#include <wiretap/wtap.h>

#include <pcap/pcap.h>

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <string.h>


static void
read_failure_message(const char *filename, int err)
{
	fprintf(stderr, "An error occurred while reading from the file \"%s\": %s.",
			filename, strerror(err) );
}

static void
failure_message(const char *msg_format, va_list ap)
{
	vfprintf(stderr, msg_format, ap);
	fprintf(stderr, "\n");
}

static void
open_failure_message(const char *filename, int err, gboolean for_writing)
{
	fprintf(stderr, "open error. filename = %s, err = %d, for_writing = %d\n",
			filename, err, for_writing);
}

static void
write_failure_message(const char *filename, int err)
{
	fprintf(stderr, "write error. filename = %s, err = %d\n",
			filename, err);
}

static nstime_t first_ts;
static nstime_t prev_cap_ts;

void fill_framedata(frame_data *fdata, uint64_t frame_number,
					const struct pcap_pkthdr *h, int ll_type)
{
	fdata->pfd = NULL;
	fdata->num = frame_number;
	fdata->pkt_len = h->len;
	fdata->cum_bytes  = 0;
	fdata->cap_len = h->caplen;
	fdata->file_off = 0;
	fdata->lnk_t = ll_type;
	fdata->abs_ts.secs = h->ts.tv_sec;
	fdata->abs_ts.nsecs = h->ts.tv_usec*1000;
	fdata->flags.passed_dfilter = 0;
	fdata->flags.encoding = PACKET_CHAR_ENC_CHAR_ASCII;
	fdata->flags.visited = 0;
	fdata->flags.marked = 0;
	fdata->flags.ref_time = 0;
	fdata->color_filter = NULL;

	if (nstime_is_unset(&first_ts) )
		first_ts = fdata->abs_ts;

	//	nstime_delta(&fdata->rel_ts, &fdata->abs_ts, &first_ts);

	if (nstime_is_unset(&prev_cap_ts) )
		prev_cap_ts = fdata->abs_ts;

	//	nstime_delta(&fdata->del_cap_ts, &fdata->abs_ts, &prev_cap_ts);
	//	fdata->del_dis_ts = fdata->del_cap_ts;
	prev_cap_ts = fdata->abs_ts;
}

static void clear_fdata(frame_data *fdata)
{
	if (fdata->pfd)
		g_slist_free(fdata->pfd);
}

capture_file cfile;

void
cap_file_init(capture_file *cf)
{
  /* Initialize the capture file struct */
  memset(cf, 0, sizeof(capture_file));
  cf->snap            = WTAP_MAX_PACKET_SIZE;
}

static void initialize_epan(void)
{
	//	int i;
	e_prefs *prefs;
	char *gpf_path, *pf_path;
	int gpf_open_errno, gpf_read_errno;
	int pf_open_errno, pf_read_errno;

	// This function is called when the program starts, to save whatever credential information
	// we'll need later, and to do other specialized platform-dependent initialization
	init_process_policies();

	init_report_err(failure_message, open_failure_message,
					read_failure_message, write_failure_message);
 
	//set timestamp type
	timestamp_set_type(TS_RELATIVE);
	timestamp_set_seconds_type(TS_SECONDS_DEFAULT);

	printf("epan_init\n");
	epan_init(register_all_protocols, register_all_protocol_handoffs,
			  NULL, NULL);
 
	// Register all non-dissector modules' preferences.
	printf("prefs_register_modules\n");
	prefs_register_modules();

	// // Read the preferences file, fill in "prefs", and return a pointer to it, 
	// // preference file has information about protocol preferences (e.g. default port)
	// prefs = read_prefs(&gpf_open_errno, &gpf_read_errno, &gpf_path,
	// 				   &pf_open_errno, &pf_read_errno, &pf_path);
  
	// if (gpf_path != NULL) {
	// 	if (gpf_open_errno != 0)
	// 		fprintf(stderr, "Can't open global preferences file \"%s\": %s.\n", pf_path, strerror(gpf_open_errno) );
    
	// 	if (gpf_read_errno != 0)
	// 		fprintf(stderr, "I/O error reading global preferences file " "\"%s\": %s.\n", pf_path, strerror(gpf_read_errno) );
	// }

	// if (pf_path != NULL) {
	// 	if (pf_open_errno != 0)
	// 		fprintf(stderr, "Can't open your preferences file \"%s\": %s.\n",pf_path, strerror(pf_open_errno));
    
	// 	if (pf_read_errno != 0)
	// 		fprintf(stderr, "I/O error reading your preferences file " "\"%s\": %s.\n", pf_path, strerror(pf_read_errno));
    
	// 	g_free(pf_path);
	// 	pf_path = NULL;

	// }

	//	cleanup_dissection();

	// Initialize the dissection engine
	//init_dissection();

	/* Set the given nstime_t to (0,maxint) to mark it as "unset"
	 * That way we can find the first frame even when a timestamp
	 * is zero */

	nstime_set_unset(&first_ts);
	nstime_set_unset(&prev_cap_ts);

	cap_file_init(&cfile);
	/* Build the column format array */
	//	build_column_format_array(&cfile.cinfo, prefs_p->num_cols, TRUE);
}

static gboolean verbose = TRUE;

void
wtap_phdr_init(struct wtap_pkthdr *phdr)
{
	memset(phdr, 0, sizeof(struct wtap_pkthdr));
	//	ws_buffer_init(&phdr->ft_specific_data, 0);
}

static void process_packet(const char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
	(void) user;
  
	// declare dissection tree data structure, it will contain all the packet information (all the layers)
	epan_dissect_t *edt;

	//declare the frame_data strcture that will be used in populating frame data
	frame_data fdata;
  
	//pseaudo header 
	union wtap_pseudo_header pseudo_header;
  
	static uint32_t frame_number = 0; /* Incremented each time libpcap gives us a packet */
  
	memset(&pseudo_header, 0, sizeof(pseudo_header) );
  
	frame_number++;	
	fill_framedata(&fdata, frame_number, h, 0);

	// get new dissection tree
	printf("epan_new\n");

	epan_t* epan = epan_new();
	printf("epan_dissect_new\n");
	edt = epan_dissect_new(epan, verbose, verbose);

	struct wtap_pkthdr phdr; /* Packet header */
	wtap_phdr_init(&phdr);
 
	// execute dissection engine on frame data
	printf("epan_dissect_run\n");
	epan_dissect_run(edt, cfile.cd_t, &phdr,
					 tvb_new_real_data(bytes, h->len, h->len),
					 &fdata, NULL);
	printf("proto_tree_print\n"); 
	if (verbose)
		proto_tree_print(NULL, edt, NULL); //print the packet information

	//free the dissection tree  
	printf("epan_dissect_free\n"); 
	epan_dissect_free(edt);
	printf("epan_free\n");
	epan_free(epan);

	// free the frame data 
	clear_fdata(&fdata);
}
void callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char*
        packet)
{
  static int count = 1;

  printf("\nPacket number [%d], length of this packet is: %d\n", count++, pkthdr->len);
  process_packet("me", pkthdr, packet);
}

int main(int argc,char **argv)
{
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    struct bpf_program fp;        /* to hold compiled program */
    bpf_u_int32 pMask;            /* subnet mask */
    bpf_u_int32 pNet;             /* ip address*/
	//    pcap_if_t *alldevs, *d;
    char dev_buff[64] = {0};
	//    int i =0;

    // Check if sufficient arguments were supplied
    if(argc < 4)
    {
        printf("\nUsage: %s [protocol][number-of-packets][if]\n",argv[0]);
        return 0;
    }

    // // Prepare a list of all the devices
    // if (pcap_findalldevs(&alldevs, errbuf) == -1)
    // {
    //     fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
    //     exit(1);
    // }

    // // Print the list to user
    // // so that a choice can be
    // // made
    // printf("\nHere is a list of available devices on your system:\n\n");
    // for(d=alldevs; d; d=d->next)
    // {
    //     printf("%d. %s", ++i, d->name);
    //     if (d->description)
    //         printf(" (%s)\n", d->description);
    //     else
    //         printf(" (Sorry, No description available for this device)\n");
    // }

    // // Ask user to provide the interface name
    // printf("\nEnter the interface name on which you want to run the packet sniffer : ");
    // fgets(dev_buff, sizeof(dev_buff)-1, stdin);

    // // Clear off the trailing newline that
    // // fgets sets
    // dev_buff[strlen(dev_buff)] = 0;

    // Check if something was provided
    // by user
	strcpy(dev_buff, argv[3]);
    if(strlen(dev_buff))
    {
        dev = dev_buff;
        printf("\n ---You opted for device [%s] to capture [%d] packets---\n\n Starting capture...",dev, (atoi)(argv[2]));
    }

    // If something was not provided
    // return error.
    if(dev == NULL)
    {
        printf("\n[%s]\n", errbuf);
        return -1;
    }

	initialize_epan();
	
    // fetch the network address and network mask
    if (pcap_lookupnet(dev, &pNet, &pMask, errbuf)) {
		printf("\npcap_lookupnet() failed due to [%s]\n", errbuf);
		return -1;
	}

    // Now, open device for sniffing
    descr = pcap_open_live(dev, BUFSIZ, 0,-1, errbuf);
    if(descr == NULL)
    {
        printf("\npcap_open_live() failed due to [%s]\n", errbuf);
        return -1;
    }

    // Compile the filter expression
    if(pcap_compile(descr, &fp, argv[1], 0, pNet) == -1)
    {
        printf("\npcap_compile() failed\n");
        return -1;
    }

    // Set the filter compiled above
    if(pcap_setfilter(descr, &fp) == -1)
    {
        printf("\npcap_setfilter() failed\n");
        exit(1);
    }

    // For every packet received, call the callback function
    // For now, maximum limit on number of packets is specified
    // by user.
    pcap_loop(descr,atoi(argv[2]), callback, NULL);

    printf("\nDone with packet sniffing!\n");
    return 0;
}
