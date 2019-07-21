
#include <pcap.h>
#include <stdio.h>
#include <sstream>
#include<iostream>

using namespace std;

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}
void printMac(const u_char* mac){
    printf("%02x %02x %02x %02x %02x %02x\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}
void isIp(const u_char* isIP){
    if(isIP[0] == 0x08 && isIP[1] == 0x00){
        printf("Layer3-IPV4) %d.%d.%d.%d \n",isIP[14],isIP[15],isIP[16],isIP[17]);
    }
}
void isTcp(const u_char* isTcp){
    if(isTcp[0] == 0x06){
        printf("Layer4-TCP) Source Port : %d \n",isTcp[11]*256 + isTcp[12]);
        printf("Layer4-TCP) Destination Port : %d\n",isTcp[13]*256 + isTcp[14]);
        if(isTcp[23] == 0x80 && isTcp[24] == 0x18){
            printf("DATA : %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",isTcp[43],isTcp[44],isTcp[45],isTcp[46],isTcp[47],isTcp[48],isTcp[49],isTcp[50],isTcp[51],isTcp[52]);
        }

    }
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL ) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("----------------------------------------------------\n");
    printf("Layer2-ETH) Destination : ");
    printMac(packet);
    printf("Layer2-ETH) Source : " );
    printMac(packet+6);
    isIp(packet+12);
    isTcp(packet+23);
    printf("----------------------------------------------------\n");

  }
  pcap_close(handle);
  return 0;
}

