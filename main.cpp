#include <stdio.h>
#include <string.h>

#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#define bool int
#include <libnetfilter_queue/pktbuff.h>
#undef bool

const char *http_methods[6]={"GET","POST","HEAD","PUT","DELETE","OPTIONS"};;

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	        struct nfq_data *nfa, void *arg){
    char buf[PATH_MAX] __attribute__ ((aligned));
	struct cb_arg *cb_arg = (struct cb_arg *)arg;

	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
    
    char *host;
	int packet_len;
    char *tcp_payload;
    int tcp_payload_len;

	struct pkt_buff *pkt;

	ph = nfq_get_msg_packet_hdr(nfa);
	if (ph) {
		id = ntohl(ph->packet_id);
	}
	payload_len = nfq_get_payload(nfa, &payload);
	pkt = pktb_alloc(AF_INET, payload, payload_len, 0);
	ip = nfq_ip_get_hdr(pkt);
	nfq_ip_set_transport_header(pkt, ip);
	tcp = nfq_tcp_get_hdr(pkt);

	if (tcp) {
        tcp_payload_len=nfq_tcp_get_payload_len(tcp, pkt) - tcp->doff * 4;
        if(tcp_payload_len > 0){
            tcp_payload = (uint8_t *)nfq_tcp_get_payload(tcp,pkt);
            for(int i=0;i<6;i++){
                if(!memcmp(tcp_payload, http_method[i], method_len[i])){
                    host = strstr((char*)tcp_payload, "Host:");
                    if(!host){
                        host += 6;
                        host = strtok(host, "\n");
                        printf("%s", host);
                    }
                }
            }

        }
	}

	pktb_free(pkt);
	return nfq_set_verdict(qh, id, NF_ACCEPT, packet_len, data);
}

int main(int argc, char *argv[]){
    struct nfq_handle *h;
	struct nfq_q_handle *qh;

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, &cb_arg);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        exit(1);
    }

    nfq_destroy_queue(qh);
    nfq_close(h)
}