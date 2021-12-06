#include <cstdio>
#include <pcap.h>
#include<sys/socket.h>
#include<sys/ioctl.h>
#include<net/if.h>
#include<arpa/inet.h>
#include<unistd.h>
#include <libnet.h>
#include <netinet/in.h>
#include "airodump.h"
#include<map>
#include<string>

#pragma pack(push, 1)
struct Param{
	Fixed_param fix;
	Tagged_param tag;
};
#pragma pack(pop)

std::map<std::string, std::pair<int, std::string>> seq;

void print() 
{
	printf("BSSID\t\t\tBeacons\t\tESSID\n");
	for(auto i : seq) {
		printf("%s\t%d\t\t%s\n", i.first.c_str(), i.second.first, i.second.second.c_str());
	}	
	printf("\n\n\n");
}

void airodump(const u_char* packet)
{
	Radiotap* radioHdr = (Radiotap*) packet;
        Beacon* pkt_bcn = (Beacon*) (packet + radioHdr->it_len);
	Param* pkt_param = (Param*) ((char*)pkt_bcn + sizeof(Beacon));

        if(pkt_bcn->type!=0x80) return;
	std::string bssid = std::string(pkt_bcn->bssid);
	std::string essid="";
	for(uint8_t i=0; i<pkt_param->tag.len; i++) 
		essid+=*(&(pkt_param->tag.essid)+i);
	
	if(seq.find(bssid)==seq.end()) seq[bssid] = {1,essid};
	else seq[bssid].first++;
	
	print();
}

void usage() {
        printf("syntax : airodump <interface>\n");
        printf("sample : airodump mon0\n");
}

int main(int argc, char* argv[]) {
    	if (argc != 2 ) {
		usage();
		return -1;
	}
	
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	printf("capture start!\n");
	while(true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet); 

		if(res==0) continue;
		if(res==PCAP_ERROR || res==PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
		
		airodump(packet);

			
	}
	
	pcap_close(handle);
}
