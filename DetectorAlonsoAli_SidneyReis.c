#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <fcntl.h>

#include <net/if.h>  //estrutura ifr
#include <netinet/ether.h> //header ethernet
#include <netinet/in.h> //definicao de protocolos
#include <arpa/inet.h> //funcoes para manipulacao de enderecos IP
//#include <netinet/ip6.h> //header ipv6

#include <net/ethernet.h> //Header do pacote Ethernet
//#include <net/if_arp.h> //header do pacote ARP

#include <netinet/in_systm.h> //tipos de dados

#include <errno.h>
#include <linux/if_ether.h>
#include <netpacket/packet.h>
#include <signal.h>

#define ETHERTYPE_LEN 2
#define MAC_ADDR_LEN 6
#define BUFFER_LEN 1518
#define BUFFSIZE 1518
#define FLAGS 67

struct ifreq ifr;

unsigned char buff[BUFFSIZE]; // buffer de recepcao

int detected = 0;

unsigned char interfaceName[5];

int m_mIndex = 0;

int sockd;

int estadoTcpConnect = 0;
int estadoTcpHalfOpening = 0;

int ethertype;
int ipv6type;

struct tipoAtaque

//ideia: lista de portas e marcar qual ataque esta sendo feito em cada


void processaTcpConnect()
{
    if(estadou que estou == 0)
    if(buff[FLAGS] == 0x02)   //recebemos um SYN
    {
        estado que estou ++
    }

    if(estado que estou == 1)
    if(buff[FLAGS] == 0x10)
        flag que conta tcpconnect ++

    if(flag que conta tcpconnect == 3)
}

void processaTcpHalfOpening()  
{
    if(buff[FLAGS] == 0x02)  //recebemos um SYN
    {

    }             
}

int main()
{
    ethertype = htons(0x86DD);
    ipv6type = 0x6;


    strcpy(interfaceName, "eth0");

    // O procedimento abaixo eh utilizado para "setar" a interface em modo promiscuo
    strcpy(ifr.ifr_name, interfaceName);
    if(ioctl(sockd, SIOCGIFINDEX, &ifr) < 0)
      printf("erro no ioctl!");
    ioctl(sockd, SIOCGIFFLAGS, &ifr);
    ifr.ifr_flags |= IFF_PROMISC;
    ioctl(sockd, SIOCSIFFLAGS, &ifr);

    if((sockd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        printf("Erro na criacao do socket.\n");
        exit(1);
    }

    while(detected != 1)
    {
        recv(sockd,(char *) &buff, sizeof(buff), 0x0);
        if(memcmp(&buff[12], &ethertype, 2) == 0)
        {
            if(buff[20] == 0x6) //tcp
            {
                processaSyn();
            }
        }
        
    }


}