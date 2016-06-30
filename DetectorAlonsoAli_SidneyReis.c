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
#define ATTACKCOUNTER 3979



struct ifreq ifr;
unsigned char buff[BUFFSIZE]; // buffer de recepcao
int detected = 0;
unsigned char interfaceName[5];
int m_mIndex = 0;
int sockd = 0;
int estadoTcpConnect = 0;
int estadoTcpHalfOpening = 0;
int ethertype;
int ipv6type;
int i;

int tcpConnectCounter = 0;

typedef struct
{
    uint16_t port;
    unsigned char macAddress[6];
    uint16_t state;
}tipoAtaque;

tipoAtaque listaTcpConnect[10000];
int listaLimiteTcpConnect = 0;

tipoAtaque listaHalfOpen[10000];
int listaLimitehalfOpen = 0;

tipoAtaque listaStealthScan[10000];
int listaLimiteStealthScan = 0;

tipoAtaque listaSynAck[10000];
int listaLimiteSynAck = 0;

//ideia: lista de portas e marcar qual ataque esta sendo feito em cada

void processaTcpConnect()
{
    if(buff[FLAGS] == 0x02)   //recebemos um SYN
    {
        int existe = 0;
        for(i = 0; i < listaLimiteTcpConnect; i++)
        {
            if(listaTcpConnect[i].port == buff[56])
            {
                existe = 1;
                break;
            }
        }
        if(!existe)
        {
            tipoAtaque novaPort;
            novaPort.port = buff[56];
            memcpy(&novaPort.port, &buff[6], 6);
            novaPort.state = 1;

            listaTcpConnect[listaLimiteTcpConnect] = novaPort;
            listaLimiteTcpConnect++;
        }

        //printf("Recebmos um SYN");
    }

    if(buff[FLAGS] == 0x10) // ACK
    {
        int existe = 0;
        int index = 0;
        for(i = 0; i < listaLimiteTcpConnect; i++)
        {
            if(listaTcpConnect[i].port == buff[56])
            {
                existe = 1;
                index = i;
                break;
            }
        }

        if(existe)
        {
            printf("chegou jiaeo\n");
            listaTcpConnect[index].state = 2;
        }
    }

    int terminalCount = 0;
    int flagTipo = 0;
    for (i = 0; i < listaLimiteTcpConnect; i++)
    {
        if(listaTcpConnect[i].state >= 1)
        {
            terminalCount++;
        }
        if(listaTcpConnect[i].state == 2)
        {
            flagTipo = 1;
        }
    }
    //printf("%d\n", terminalCount);
    if(terminalCount >= ATTACKCOUNTER && flagTipo == 1)
    {
        printf("Ataque de TCPConnect acontecendo, xessus\n");
    }
    else if(terminalCount >= ATTACKCOUNTER)
    {
        printf("Ataque de TCP Connect ou Half-Opening acontecendo, doublexessus\n");
    }
}

void processaTcpHalfOpening()
{
    if(buff[FLAGS] == 0x02)   //recebemos um SYN
    {
        int existe = 0;
        for(i = 0; i < listaLimitehalfOpen; i++)
        {
            if(listaHalfOpen[i].port == buff[56])
            {
                existe = 1;
                break;
            }
        }

        if(!existe)
        {
            tipoAtaque novaPort;
            novaPort.port = buff[56];
            memcpy(&novaPort.port, &buff[6], 6);
            novaPort.state = 1;

            listaHalfOpen[listaLimitehalfOpen] = novaPort;
            listaLimitehalfOpen++;
        }

        //printf("Recebmos um SYN");
    }

    if(buff[FLAGS] == 0x04) // RST
    {
        int existe = 0;
        int index = 0;
        for(i = 0; i < listaLimitehalfOpen; i++)
        {
            if(listaHalfOpen[i].port == buff[56])
            {
                existe = 1;
                index = i;
                break;
            }
        }

        if(existe)
        {
            printf("chegou jiaeo\n");
            listaHalfOpen[index].state = 2;
        }
    }

    int terminalCount = 0;
    int flagTipo = 0;
    for (i = 0; i < listaLimitehalfOpen; i++)
    {
        if(listaHalfOpen[i].state >= 1)
        {
            terminalCount++;
        }
        if(listaHalfOpen[i].state == 2)
        {
            flagTipo = 1;
        }
    }
    //printf("%d\n", terminalCount);
    if(terminalCount >= ATTACKCOUNTER && flagTipo == 1)
    {
        printf("Ataque de TCP Half-Opening acontecendo, xessus\n");
    }
    else if(terminalCount >= ATTACKCOUNTER)
    {
        printf("Ataque de TCP Connect ou Half-Opening acontecendo, doublexessus\n");
    }
}

void processaStealthScan
{
    if(buff[FLAGS] == 0x01)   //recebemos um FIN
    {
        int existe = 0;
        for(i = 0; i < listaLimiteStealthScan; i++)
        {
            if(listaStealthScan[i].port == buff[56])
            {
                existe = 1;
                break;
            }
        }

        if(!existe)
        {
            tipoAtaque novaPort;
            novaPort.port = buff[56];
            memcpy(&novaPort.port, &buff[6], 6);
            novaPort.state = 1;

            listaStealthScan[listaLimiteStealthScan] = novaPort;
            listaLimiteStealthScan++;
        }

        //printf("Recebmos um FIN");
    }

    int terminalCount = 0;
    for (i = 0; i < listaLimiteStealthScan; i++)
    {
        if(listaStealthScan[i].state >= 1)
        {
            terminalCount++;
        }
    }
    //printf("%d\n", terminalCount);
    if(terminalCount >= ATTACKCOUNTER)
    {
        printf("Ataque de Stealth Scan acontecendo, xessus\n");
    }
}

void processaSynAck
{
    if(buff[FLAGS] == 0x12)   //recebemos um SYN/ACK
    {
        int existe = 0;
        for(i = 0; i < listaLimiteSynAck; i++)
        {
            if(listaSynAck[i].port == buff[56])
            {
                existe = 1;
                break;
            }
        }

        if(!existe)
        {
            tipoAtaque novaPort;
            novaPort.port = buff[56];
            memcpy(&novaPort.port, &buff[6], 6);
            novaPort.state = 1;

            listaSynAck[listaLimiteSynAck] = novaPort;
            listaLimiteSynAck++;
        }

        //printf("Recebmos um SYN/ACK");
    }

    int terminalCount = 0;
    for (i = 0; i < listaLimiteSynAck; i++)
    {
        if(listaSynAck[i].state >= 1)
        {
            terminalCount++;
        }
    }
    //printf("%d\n", terminalCount);
    if(terminalCount >= ATTACKCOUNTER)
    {
        printf("Ataque de SYN/ACK acontecendo, xessus\n");
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
      printf("erro no ioctl!\n");
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
                processaTcpConnect();
                processaTcpHalfOpening();
                processaStealthScan();
                processaSynAck();
            }
        }

    }


}