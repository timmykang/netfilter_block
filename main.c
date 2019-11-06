
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

struct packet_id {
	int id;
	bool chk;
};

char * host;

bool packet_check(unsigned char *data) {
	uint32_t ip_hdr_len, ip_pkt_len, tcp_hdr_len, tcp_data_len;
	unsigned char * tcp_data;
	ip_hdr_len = ((*(uint8_t *)data) & 0x0F) * 4;
	ip_pkt_len = ntohs(*(uint16_t *)(data + 2));
	if(*(uint8_t *)(data + 9) != 0x06)
		return false;
	tcp_hdr_len = (((*(uint8_t *)(data + ip_hdr_len + 12)) & 0xF0) >> 4) * 4;
	tcp_data_len = ip_pkt_len - (ip_hdr_len + tcp_hdr_len);
	if(tcp_data_len == 0)
		return false;
	tcp_data = data + ip_hdr_len + tcp_hdr_len;
	if(memcmp(tcp_data, "GET", 3) && memcmp(tcp_data, "POST", 4) && memcmp(tcp_data, "HEAD", 4) && memcmp(tcp_data, "PUT", 3) && memcmp(tcp_data, "DELETE", 6) && memcmp(tcp_data, "OPTIONS", 7))
		return false;
	for(int i = 0; i< tcp_data_len - 6; i++) {
		if(!memcmp(tcp_data + i, "HOST: ", 6)) {
			printf("\n---------------\n%s\n-------------\n",tcp_data+i+6);
			if(!memcmp(tcp_data + i + 6, host, strlen(host)))
				return true;
			else
				return false;
		}
	}
	return false;
}

/* returns packet id*/
static packet_id print_pkt (struct nfq_data *tb)
{
	int len;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	struct packet_id ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		ret.id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, ret.id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	len = nfq_get_payload(tb, &data);
	ret.chk = packet_check(data);

	if (len >= 0)
		printf("payload_len=%d ", len);

	fputc('\n', stdout);

	return ret;
}
	

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	struct packet_id pkt_id = print_pkt(nfa);
	printf("entering callback\n");
	if(pkt_id.chk == true)
	{
		printf("Packet Drop success\n");
		exit(1);
		return nfq_set_verdict(qh, pkt_id.id, NF_DROP, 0, NULL);
	}
	else
		return nfq_set_verdict(qh, pkt_id.id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));
	char * host;

	host = argv[1];

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
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. Please, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
