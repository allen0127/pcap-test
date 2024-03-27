#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};
struct Packet{
	u_int8_t mac_dst[6];
	u_int8_t mac_src[6];
	u_int8_t eth_type[2];
	u_int8_t ip_etc[12];
	u_int8_t ip_src[4];
	u_int8_t ip_dst[4];
	u_int8_t tcp_src[2];
	u_int8_t tcp_dst[2];
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		//printf("%u bytes captured\n", header->caplen);
		struct Packet* pct=packet;
		if(pct->eth_type[0]!=0x08||pct->eth_type[1]!=0x00||pct->ip_etc[9]!=0x06){
			printf("No\n");
			continue;
		}

		printf("\nmac dst: ");
		for(int i=0;i<6;i++){
			printf("%02x ",pct->mac_dst[i]);
		}
		printf("\nmac src: ");
		for(int i=0;i<6;i++){
			printf("%02x ",pct->mac_src[i]);
		}
		printf("\nip src: ");
		for(int i=0;i<4;i++){
			printf("%02x ",pct->ip_src[i]);
		}
		printf("\nip dst: ");
		for(int i=0;i<4;i++){
			printf("%02x ",pct->ip_dst[i]);
		}
		printf("\ntcp src: ");
		for(int i=0;i<2;i++){
			printf("%02x ",pct->tcp_src[i]);
		}
		printf("\ntcp dst: ");
		for(int i=0;i<2;i++){
			printf("%02x ",pct->tcp_dst[i]);
		}
		printf("\ndata: ");
		for(int i=0;i<header->caplen-54&&i<20;i++){
			printf("%02x ",packet[i+54]);
		}
		printf("\n====================");

	}


	pcap_close(pcap);
}
