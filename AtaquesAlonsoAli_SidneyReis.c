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

typedef struct
{
    uint32_t firstLine; //4 bits type, 8 bits traffic class, 20 Flow label
    uint16_t payloadLength; //auto explicativo
    uint8_t nextHeader; //auto explicativo
    uint8_t hopLimit; //auto explicativo
} ip6_hdr;

typedef struct
{
	uint16_t sourcePort;
	uint16_t destPort;
	uint32_t seqNumber;
	uint32_t ackNumber;
	uint16_t dataOffAndFlags;
	uint16_t window;
	uint16_t checksum;
	uint16_t urgentPointer;
	uint32_t options;
} tcp_hdr;

typedef struct
{
  unsigned char sourceAddress[16];
  unsigned char destinationAddress[16];
  uint32_t tcpLength;
  uint32_t zeros_nextHeader;
} pseudo_hdr;

static volatile int keepRunning = 1;

// Atencao!! Confira no /usr/include do seu sisop o nome correto
// das estruturas de dados dos protocolos.

typedef unsigned char MacAddress[MAC_ADDR_LEN];
extern int errno;


unsigned char bufferEnt[BUFFER_LEN], bufferSai[BUFFER_LEN];

int sockEnt;
int sockSai;
int on;
struct ifreq ifr;

unsigned char localMac[6]; //MAC da nossa máquina
unsigned char targetMac[6]; //MAC do host que fez o ARP Request original

unsigned char localIp[16]; //IPV6 da nossa maquina
unsigned char targetIp[16]; //IPV6 do alvo

unsigned short int etherType;

unsigned char interfaceName[5];

struct sockaddr_ll destAddr = {0};

/*
 * Copyright (c) 1989, 1993
 *      The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Mike Muuss.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the University of
 *      California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * in_cksum --
 *      Checksum routine for Internet Protocol family headers (C Version)
 */
unsigned short in_cksum(unsigned short *addr,int len)
{
        register int sum = 0;
        u_short answer = 0;
        register u_short *w = addr;
        register int nleft = len;

        /*
         * Our algorithm is simple, using a 32 bit accumulator (sum), we add
         * sequential 16 bit words to it, and at the end, fold back all the
         * carry bits from the top 16 bits into the lower 16 bits.
         */
        while (nleft > 1) {
                sum += *w++;
                nleft -= 2;
        }

        /* mop up an odd byte, if necessary */
        if (nleft == 1) {
                *(u_char *)(&answer) = *(u_char *)w ;
                sum += answer;
        }

        /* add back carry outs from top 16 bits to low 16 bits */
        sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
        sum += (sum >> 16);                     /* add carry */
        answer = ~sum;                          /* truncate to 16 bits */
        return(answer);
}

void acquireMAC() {

    int fd;
    struct ifreq ifr;
    char *iface = interfaceName;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);

    ioctl(fd, SIOCGIFHWADDR, &ifr);

    close(fd);



    memcpy(localMac, (unsigned char *)ifr.ifr_hwaddr.sa_data, sizeof(char) * 6);
}

void intHandler(int dummy) {
    keepRunning = 0;
}

void syn_ack()
{
    sockEnt = 0;
    sockSai = 0;

    int i;

    uint16_t sorcPortNum = 3000; // exemplo
    uint16_t destPortNum = 1024; // exemplo

    uint16_t portLimit = 5002;

    if((sockSai = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        printf("Erro na criacao do socket.\n");
        exit(1);
    }

    if((sockEnt = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        printf("Erro na criacao do socket.\n");
        exit(1);
    }

    int flags = fcntl(sockEnt, F_GETFL, 0);
    fcntl(sockEnt, F_SETFL, flags | O_NONBLOCK);
    tcp_hdr tcp;

    tcp.sourcePort = htons(sorcPortNum);
    tcp.destPort = htons(destPortNum);
    tcp.seqNumber = htons(1);
    tcp.ackNumber = htons(0);
    tcp.dataOffAndFlags = htons((0x6 << 12) + 0x12); //0x1 = SYN/ack
    tcp.window = htons(0xff);

    tcp.checksum = htons(0);
    tcp.urgentPointer = htons(0); //TODO: avaliar
    tcp.options = 0;

    pseudo_hdr pseudoHeader;
    memcpy(&pseudoHeader.sourceAddress, &localIp, sizeof(localIp));
    memcpy(&pseudoHeader.destinationAddress, &targetIp, sizeof(targetIp));
    pseudoHeader.tcpLength = htons(sizeof(tcp));
    pseudoHeader.zeros_nextHeader = htons(6);

    int tcpChecksumSize = sizeof(tcp) + sizeof(pseudoHeader);
    unsigned char pseudoWithTcp[2*tcpChecksumSize];

    for(i = 0; i < tcpChecksumSize; i++)
    {
        pseudoWithTcp[i] = 0;
    }
    memcpy(&pseudoWithTcp, &pseudoHeader, sizeof(pseudoHeader));
    memcpy(&pseudoWithTcp[sizeof(pseudoHeader)], &tcp, sizeof(tcp));

    tcp.checksum = in_cksum((unsigned short*)pseudoWithTcp, tcpChecksumSize);

    ip6_hdr ip6;
    uint32_t tipo =0x6 << 12;
    ip6.firstLine = htons(tipo);
    ip6.payloadLength = htons(sizeof(tcp_hdr));
    ip6.nextHeader = 6;
    ip6.hopLimit = 5;

    memcpy( &bufferSai[54], &tcp, sizeof(tcp_hdr));

    memcpy(&bufferSai[14], &ip6,  8); //8 bytes = tamanho ip6 struct
    memcpy(&bufferSai[22],&localIp, 16);
    memcpy(&bufferSai[38], &targetIp, 16);

    memcpy(&bufferSai, &targetMac, 6);
    memcpy(&bufferSai[6], &localMac, 6);
    memcpy(&bufferSai[12], &etherType, 2);

    //varedura de portas
  while(destPortNum <= portLimit)
  {
    if(sendto(sockSai, bufferSai, 14 + sizeof(tcp_hdr) + sizeof(ip6_hdr) + 2 * 16 /*tamanho dos enderecos ipv6*/ + 80, 0, (struct sockaddr *)&(destAddr), sizeof(struct sockaddr_ll)) < 0)
    {
        printf("ERROR! sendto() \n");
        exit(1);
    }
    int i = 15000;
    while(i != 0)
    {
        if(recv(sockEnt,(char *) &bufferEnt, sizeof(bufferEnt), 0x0) != 0)
        {
            if(memcmp(targetMac, &bufferEnt[6], 6) == 0)
            {
                //printf("Lalaioss%s\n", bufferEnt);
                break;
            }
        }

        //printf("%i\n", i)
        //printf("%zd\n", recv(sockEnt,(char *) &bufferEnt, sizeof(bufferEnt), 0x0));
        i--;
    }


    if(i != 0)
    {
        if(bufferEnt[54 + 12 + 1] == 4) //54 offset pro header tcp, 12 pro campo de dataoff + flags , 1 pro campo de flags
        {
            //recebido eh syn/ack
            printf("Porta %i: aberta\n", destPortNum);
        }
        else
        {
            //printf("Flag desconhecido\n");
            printf("Porta %i: fechada\n", destPortNum);
        }
    }
    else
    {
        printf("Porta %i: fechada\n", destPortNum);
    }

    destPortNum++;
    tcp.destPort = htons(destPortNum);
    tcp.seqNumber = htons(1);
    tcp.ackNumber = htons(0);
    tcp.dataOffAndFlags = htons((0x6 << 12) + 0x1);
    tcp.checksum = 0;

    memcpy(&pseudoWithTcp[sizeof(pseudoHeader)], &tcp, sizeof(tcp)); //temos que calcular de novo o checksum com os novos dados, olha la

    tcp.checksum = in_cksum((unsigned short*)pseudoWithTcp, tcpChecksumSize); //calcula

    memcpy( &bufferSai[54], &tcp, sizeof(tcp_hdr)); //vai powrra
  }

  printf("Terminou SYN/ACK\n");
}

void stealthscan()
{
    sockEnt = 0;
    sockSai = 0;

    int i;

    uint16_t sorcPortNum = 3000; // exemplo
    uint16_t destPortNum = 1024; // exemplo

    uint16_t portLimit = 5002;

    if((sockSai = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        printf("Erro na criacao do socket.\n");
        exit(1);
    }

    if((sockEnt = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        printf("Erro na criacao do socket.\n");
        exit(1);
    }

    int flags = fcntl(sockEnt, F_GETFL, 0);
    fcntl(sockEnt, F_SETFL, flags | O_NONBLOCK);
    tcp_hdr tcp;

    tcp.sourcePort = htons(sorcPortNum);
    tcp.destPort = htons(destPortNum);
    tcp.seqNumber = htons(1);
    tcp.ackNumber = htons(0);
    tcp.dataOffAndFlags = htons((0x6 << 12) + 0x1); //0x1 = FIN
    tcp.window = htons(0xff);

    tcp.checksum = htons(0);
    tcp.urgentPointer = htons(0); //TODO: avaliar
    tcp.options = 0;

    pseudo_hdr pseudoHeader;
    memcpy(&pseudoHeader.sourceAddress, &localIp, sizeof(localIp));
    memcpy(&pseudoHeader.destinationAddress, &targetIp, sizeof(targetIp));
    pseudoHeader.tcpLength = htons(sizeof(tcp));
    pseudoHeader.zeros_nextHeader = htons(6);

    int tcpChecksumSize = sizeof(tcp) + sizeof(pseudoHeader);
    unsigned char pseudoWithTcp[2*tcpChecksumSize];

    for(i = 0; i < tcpChecksumSize; i++)
    {
        pseudoWithTcp[i] = 0;
    }
    memcpy(&pseudoWithTcp, &pseudoHeader, sizeof(pseudoHeader));
    memcpy(&pseudoWithTcp[sizeof(pseudoHeader)], &tcp, sizeof(tcp));

    tcp.checksum = in_cksum((unsigned short*)pseudoWithTcp, tcpChecksumSize);

    ip6_hdr ip6;
    uint32_t tipo =0x6 << 12;
    ip6.firstLine = htons(tipo);
    ip6.payloadLength = htons(sizeof(tcp_hdr));
    ip6.nextHeader = 6;
    ip6.hopLimit = 5;

    memcpy( &bufferSai[54], &tcp, sizeof(tcp_hdr));

    memcpy(&bufferSai[14], &ip6,  8); //8 bytes = tamanho ip6 struct
    memcpy(&bufferSai[22],&localIp, 16);
    memcpy(&bufferSai[38], &targetIp, 16);

    memcpy(&bufferSai, &targetMac, 6);
    memcpy(&bufferSai[6], &localMac, 6);
    memcpy(&bufferSai[12], &etherType, 2);

    //varedura de portas
  while(destPortNum <= portLimit)
  {
    if(sendto(sockSai, bufferSai, 14 + sizeof(tcp_hdr) + sizeof(ip6_hdr) + 2 * 16 /*tamanho dos enderecos ipv6*/ + 80, 0, (struct sockaddr *)&(destAddr), sizeof(struct sockaddr_ll)) < 0)
    {
        printf("ERROR! sendto() \n");
        exit(1);
    }
    int i = 15000;
    while(i != 0)
    {
        if(recv(sockEnt,(char *) &bufferEnt, sizeof(bufferEnt), 0x0) != 0)
        {
            if(memcmp(targetMac, &bufferEnt[6], 6) == 0)
            {
                printf("Lalaioss%s\n", bufferEnt);
                break;
            }
        }

        //printf("%i\n", i)
        //printf("%zd\n", recv(sockEnt,(char *) &bufferEnt, sizeof(bufferEnt), 0x0));
        i--;
    }


    if(i != 0)
    {
        if(bufferEnt[54 + 12 + 1] == 4) //54 offset pro header tcp, 12 pro campo de dataoff + flags , 1 pro campo de flags
        {
            //recebido eh rst
            printf("Porta %i: fechada\n", destPortNum);
        }
        else
        {
            //printf("Flag desconhecido\n");
            printf("Porta %i: aberta\n", destPortNum);
        }
    }
    else
    {
        printf("Porta %i: aberta\n", destPortNum);
    }

    destPortNum++;
    tcp.destPort = htons(destPortNum);
    tcp.seqNumber = htons(1);
    tcp.ackNumber = htons(0);
    tcp.dataOffAndFlags = htons((0x6 << 12) + 0x1);
    tcp.checksum = 0;

    memcpy(&pseudoWithTcp[sizeof(pseudoHeader)], &tcp, sizeof(tcp)); //temos que calcular de novo o checksum com os novos dados, olha la

    tcp.checksum = in_cksum((unsigned short*)pseudoWithTcp, tcpChecksumSize); //calcula

    memcpy( &bufferSai[54], &tcp, sizeof(tcp_hdr)); //vai powrra
  }

  printf("Terminou Stealth Scan\n");
}

void tcpconnect()
{
    sockEnt = 0;
    sockSai = 0;

    int i;

    uint16_t sorcPortNum = 3000; // exemplo
    uint16_t destPortNum = 1024; // exemplo

    uint16_t portLimit = 5002;

    if((sockSai = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        printf("Erro na criacao do socket.\n");
        exit(1);
    }

    if((sockEnt = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        printf("Erro na criacao do socket.\n");
        exit(1);
    }

    int flags = fcntl(sockEnt, F_GETFL, 0);
    fcntl(sockEnt, F_SETFL, flags | O_NONBLOCK);

    tcp_hdr tcp;

    tcp.sourcePort = htons(sorcPortNum);
    tcp.destPort = htons(destPortNum);
    tcp.seqNumber = htons(1);
    tcp.ackNumber = htons(0);
    tcp.dataOffAndFlags = htons((0x6 << 12) + 0x2);
    tcp.window = htons(0xff);

    tcp.checksum = htons(0);
    tcp.urgentPointer = htons(0); //TODO: avaliar
    tcp.options = 0;


    pseudo_hdr pseudoHeader;
    memcpy(&pseudoHeader.sourceAddress, &localIp, sizeof(localIp));
    memcpy(&pseudoHeader.destinationAddress, &targetIp, sizeof(targetIp));
    pseudoHeader.tcpLength = htons(sizeof(tcp));
    pseudoHeader.zeros_nextHeader = htons(6);

    int tcpChecksumSize = sizeof(tcp) + sizeof(pseudoHeader);
    unsigned char pseudoWithTcp[2*tcpChecksumSize];

    for(i = 0; i < tcpChecksumSize; i++)
    {
        pseudoWithTcp[i] = 0;
    }
    memcpy(&pseudoWithTcp, &pseudoHeader, sizeof(pseudoHeader));
    memcpy(&pseudoWithTcp[sizeof(pseudoHeader)], &tcp, sizeof(tcp));

    tcp.checksum = in_cksum((unsigned short*)pseudoWithTcp, tcpChecksumSize);

    /*int tcpAndPseudoSize = sizeof(tcp_hdr) + sizeof(pseudo_hdr);
    int tcpSize = htons(sizeof(tcp_hdr));
    uint32_t nxtHdr = htons(6);
    unsigned short pseudoWithTcp[tcpAndPseudoSize];
    for(i = 0; i < tcpAndPseudoSize; i++)
    {
        pseudoWithTcp[i] = 0;
    }
    memcpy(pseudoWithTcp, localIp, 16);
    memcpy(&pseudoWithTcp[16], targetIp, 16);
    memcpy(&pseudoWithTcp[32], &tcpSize, 4);
    memcpy(&pseudoWithTcp[36], &nxtHdr, 4);
    memcpy(&pseudoWithTcp[40], &tcp, sizeof(tcp_hdr));

    tcp.checksum = htons(in_cksum(pseudoWithTcp, tcpAndPseudoSize));*/



    ip6_hdr ip6;
    uint32_t tipo =0x6 << 12;
    ip6.firstLine = htons(tipo);
    ip6.payloadLength = htons(sizeof(tcp_hdr));
    ip6.nextHeader = 6;
    ip6.hopLimit = 5;

    memcpy( &bufferSai[54], &tcp, sizeof(tcp_hdr));

    memcpy(&bufferSai[14], &ip6,  8); //8 bytes = tamanho ip6 struct
    memcpy(&bufferSai[22],&localIp, 16);
    memcpy(&bufferSai[38], &targetIp, 16);

    memcpy(&bufferSai, &targetMac, 6);
    memcpy(&bufferSai[6], &localMac, 6);
    memcpy(&bufferSai[12], &etherType, 2);



    //varedura de portas
  while(destPortNum <= portLimit)
  {
    if(sendto(sockSai, bufferSai, 14 + sizeof(tcp_hdr) + sizeof(ip6_hdr) + 2 * 16 /*tamanho dos enderecos ipv6*/ , 0, (struct sockaddr *)&(destAddr), sizeof(struct sockaddr_ll)) < 0)
    {
        printf("ERROR! sendto() \n");
        exit(1);
    }

    int i = 15000;
    while(i != 0)
    {
        if(recv(sockEnt,(char *) &bufferEnt, sizeof(bufferEnt), 0x0) != 0)
        {
            if(memcmp(targetMac, &bufferEnt[6], 6) == 0)
            {
                //printf("Lalaioss%s\n", bufferEnt);
                break;
            }
        }

        //printf("%i\n", i);
        //printf("%zd\n", recv(sockEnt,(char *) &bufferEnt, sizeof(bufferEnt), 0x0));
        i--;
    }


    if(i != 0)
    {
        if(bufferEnt[54 + 12 + 1] == 0x12) //54 offset pro header tcp, 12 pro campo de dataoff + flags , 1 pro campo de flags
        {
            //recebido eh syn/ack
            printf("Porta %i: aberta\n", destPortNum);

            tcp_hdr received;
            memcpy(&received, &bufferEnt[54], sizeof(tcp_hdr));

            tcp.dataOffAndFlags = htons((0x6 << 12) + 0x10); //ack
            tcp.seqNumber = received.ackNumber;
            tcp.ackNumber = received.seqNumber+1;
            tcp.checksum = 0;

            memcpy(&pseudoWithTcp[sizeof(pseudoHeader)], &tcp, sizeof(tcp)); //temos que calcular de novo o checksum com os novos dados, olha la

            tcp.checksum = in_cksum((unsigned short*)pseudoWithTcp, tcpChecksumSize); //calcula

            memcpy( &bufferSai[54], &tcp, sizeof(tcp_hdr)); //vai powrra
            //terminou de construir o ack

            if(sendto(sockSai, bufferSai, 14 + sizeof(tcp_hdr) + sizeof(ip6_hdr) + 2 * 16 /*tamanho dos enderecos ipv6*/ + 80, 0, (struct sockaddr *)&(destAddr), sizeof(struct sockaddr_ll)) < 0)
            {
                printf("ERROR! sendto() no envio do ACK tcpconnect\n");
                exit(1);
            }
        }
        else
        {
            //printf("Flag desconhecido\n");
            printf("Porta %i: fechada\n", destPortNum);
        }
    }
    else
    {
        printf("Porta %i: fechada\n", destPortNum);
    }

    destPortNum++; //avanca porta a ser atacada
    tcp.destPort = htons(destPortNum); //muda a porta
    tcp.seqNumber = htons(1); //reseta seqNumber
    tcp.ackNumber = htons(0); //reseta ackNumber
    tcp.dataOffAndFlags = htons((0x6 << 12) + 0x2); // bota flag de volta para syn
    tcp.checksum = 0;

    memcpy(&pseudoWithTcp[sizeof(pseudoHeader)], &tcp, sizeof(tcp)); //temos que calcular de novo o checksum com os novos dados, olha la

    tcp.checksum = in_cksum((unsigned short*)pseudoWithTcp, tcpChecksumSize); //calcula

    memcpy( &bufferSai[54], &tcp, sizeof(tcp_hdr)); //vai powrra
  }
  printf("Terminou TCP Connect\n");
}

void tcphalfopening()
{
    sockEnt = 0;
    sockSai = 0;

    int i;

    uint16_t sorcPortNum = 3000; // exemplo
    uint16_t destPortNum = 1024; // exemplo

    uint16_t portLimit = 5002;

    if((sockSai = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        printf("Erro na criacao do socket.\n");
        exit(1);
    }

    if((sockEnt = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        printf("Erro na criacao do socket.\n");
        exit(1);
    }

    int flags = fcntl(sockEnt, F_GETFL, 0);
    fcntl(sockEnt, F_SETFL, flags | O_NONBLOCK);
    tcp_hdr tcp;

    tcp.sourcePort = htons(sorcPortNum);
    tcp.destPort = htons(destPortNum);
    tcp.seqNumber = htons(1);
    tcp.ackNumber = htons(0);
    tcp.dataOffAndFlags = htons((0x6 << 12) + 0x2);
    tcp.window = htons(0xff);

    tcp.checksum = htons(0);
    tcp.urgentPointer = htons(0); 
    tcp.options = 0;

    pseudo_hdr pseudoHeader;
    memcpy(&pseudoHeader.sourceAddress, &localIp, sizeof(localIp));
    memcpy(&pseudoHeader.destinationAddress, &targetIp, sizeof(targetIp));
    pseudoHeader.tcpLength = htons(sizeof(tcp));
    pseudoHeader.zeros_nextHeader = htons(6);

    int tcpChecksumSize = sizeof(tcp) + sizeof(pseudoHeader);
    unsigned char pseudoWithTcp[2*tcpChecksumSize];

    for(i = 0; i < tcpChecksumSize; i++)
    {
        pseudoWithTcp[i] = 0;
    }
    memcpy(&pseudoWithTcp, &pseudoHeader, sizeof(pseudoHeader));
    memcpy(&pseudoWithTcp[sizeof(pseudoHeader)], &tcp, sizeof(tcp));

    tcp.checksum = in_cksum((unsigned short*)pseudoWithTcp, tcpChecksumSize);

    ip6_hdr ip6;
    uint32_t tipo =0x6 << 12;
    ip6.firstLine = htons(tipo);
    ip6.payloadLength = htons(sizeof(tcp_hdr));
    ip6.nextHeader = 6;
    ip6.hopLimit = 5;

    memcpy( &bufferSai[54], &tcp, sizeof(tcp_hdr));

    memcpy(&bufferSai[14], &ip6,  8); //8 bytes = tamanho ip6 struct
    memcpy(&bufferSai[22],&localIp, 16);
    memcpy(&bufferSai[38], &targetIp, 16);

    memcpy(&bufferSai, &targetMac, 6);
    memcpy(&bufferSai[6], &localMac, 6);
    memcpy(&bufferSai[12], &etherType, 2);

    //varedura de portas
  while(destPortNum <= portLimit)
  {
    if(sendto(sockSai, bufferSai, 14 + sizeof(tcp_hdr) + sizeof(ip6_hdr) + 2 * 16 /*tamanho dos enderecos ipv6*/ + 80, 0, (struct sockaddr *)&(destAddr), sizeof(struct sockaddr_ll)) < 0)
    {
        printf("ERROR! sendto() \n");
        exit(1);
    }
    int i = 15000;
    while(i != 0)
    {
        if(recv(sockEnt,(char *) &bufferEnt, sizeof(bufferEnt), 0x0) != 0)
        {
            if(memcmp(targetMac, &bufferEnt[6], 6) == 0)
            {
                //printf("Lalaioss%s\n", bufferEnt);
                break;
            }
        }

        //printf("%i\n", i);
        //printf("%zd\n", recv(sockEnt,(char *) &bufferEnt, sizeof(bufferEnt), 0x0));
        i--;
    }


    if(i != 0)
    {
        if(bufferEnt[54 + 12 + 1] == 0x12) //54 offset pro header tcp, 12 pro campo de dataoff + flags , 1 pro campo de flags
        {
            //recebido eh syn/ack
            printf("Porta %i: aberta\n", destPortNum);

            tcp_hdr received;
            memcpy(&received, &bufferEnt[54], sizeof(tcp_hdr));

            tcp.dataOffAndFlags = htons((0x6 << 12) + 0x4); //rst
            tcp.seqNumber = received.ackNumber;
            tcp.ackNumber = received.seqNumber+1;
            tcp.checksum = 0;

            memcpy(&pseudoWithTcp[sizeof(pseudoHeader)], &tcp, sizeof(tcp)); //temos que calcular de novo o checksum com os novos dados, olha la

            tcp.checksum = in_cksum((unsigned short*)pseudoWithTcp, tcpChecksumSize); //calcula

            memcpy( &bufferSai[54], &tcp, sizeof(tcp_hdr)); //vai powrra
            //terminou de construir o ack

            if(sendto(sockSai, bufferSai, 14 + sizeof(tcp_hdr) + sizeof(ip6_hdr) + 2 * 16 /*tamanho dos enderecos ipv6*/ + 80, 0, (struct sockaddr *)&(destAddr), sizeof(struct sockaddr_ll)) < 0)
            {
                printf("ERROR! sendto() no envio do ACK tcp half opening\n");
                exit(1);
            }
        }
        else
        {
            //printf("Flag desconhecido\n");
            printf("Porta %i: fechada\n", destPortNum);
        }
    }
    else
    {
        printf("Porta %i: fechada\n", destPortNum);
    }

    destPortNum++; //avanca porta a ser atacada
    tcp.destPort = htons(destPortNum); //muda a porta
    tcp.seqNumber = htons(1); //reseta seqNumber
    tcp.ackNumber = htons(0); //reseta ackNumber
    tcp.dataOffAndFlags = htons((0x6 << 12) + 0x2); // bota flag de volta para syn
    tcp.checksum = 0;

    memcpy(&pseudoWithTcp[sizeof(pseudoHeader)], &tcp, sizeof(tcp)); //temos que calcular de novo o checksum com os novos dados, olha la

    tcp.checksum = in_cksum((unsigned short*)pseudoWithTcp, tcpChecksumSize); //calcula

    memcpy( &bufferSai[54], &tcp, sizeof(tcp_hdr)); //vai powrra
  }





  printf("Terminou TCP Half opening\n");
}

/*
void readTargetMacAndIP()
{
    FILE *fp;
    int c;
    fp = fopen("target.txt","r");
    if(fp != NULL)
    {
        printf("%s\n", "cara");
        fread(targetMac,1, 6, fp);
        fread(&targetIp,1, 16, fp);
        fclose(fp);
    }
    else
    {
        printf("%s\n", "Nao foi encontrado arquivo target.txt. Modo de uso: inserir primeiro mac e depois endereco ipv6");
        exit(0);
    }


}*/

void readTargetMacAndIP()
{
    unsigned int iMac[6];
    char macStr[17];
    unsigned int iIpv6[16];
    char ipv6Str[39];
    int i;

    printf("%s\n", "Insira MAC da vitima: (usar formato padrao, i.e: a4:f3:21:44:55:fe)");
    scanf("%s", macStr);

    sscanf(macStr, "%x:%x:%x:%x:%x:%x", &iMac[0], &iMac[1], &iMac[2], &iMac[3], &iMac[4], &iMac[5]);
    for(i=0;i<6;i++)
        targetMac[i] = (unsigned char)iMac[i];

    printf("%s\n", "Insira endereco IPv6 da vitima: (usar formato padrao, i.e: fe80:f333:2121:4451:5578:fe23:abcd:3223)");
    scanf("%s", ipv6Str);

    sscanf(ipv6Str, "%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x", &iIpv6[0], &iIpv6[1], &iIpv6[2], &iIpv6[3], &iIpv6[4], &iIpv6[5], &iIpv6[6],&iIpv6[7],&iIpv6[8],&iIpv6[9],&iIpv6[10],&iIpv6[11],&iIpv6[12],&iIpv6[13],&iIpv6[14],&iIpv6[15]);
    for(i=0;i<16;i++)
    {
        targetIp[i] = (unsigned char)iIpv6[i];
    }
}

void setupTeste()
{
    localMac[0] = 0xa4;
    localMac[1] = 0x1f;
    localMac[2] = 0x72;
    localMac[3] = 0xf5;
    localMac[4] = 0x90;
    localMac[5] = 0x12;

    localIp[0] = 0xfe;
    localIp[1] = 0x80;
    localIp[2] = 0x00;
    localIp[3] = 0x00;
    localIp[4] = 0x00;
    localIp[5] = 0x00;
    localIp[6] = 0x00;
    localIp[7] = 0x00;
    localIp[8] = 0xa6;
    localIp[9] = 0x1f;
    localIp[10] = 0x72;
    localIp[11] = 0xff;
    localIp[12] = 0xfe;
    localIp[13] = 0xf5;
    localIp[14] = 0x90;
    localIp[15] = 0x12;

    targetMac[0] = 0xa4;
    targetMac[1] = 0x1f;
    targetMac[2] = 0x72;
    targetMac[3] = 0xf5;
    targetMac[4] = 0x90;
    targetMac[5] = 0x50;

    targetIp[0] = 0xfe;
    targetIp[1] = 0x80;
    targetIp[2] = 0x00;
    targetIp[3] = 0x00;
    targetIp[4] = 0x00;
    targetIp[5] = 0x00;
    targetIp[6] = 0x00;
    targetIp[7] = 0x00;
    targetIp[8] = 0xa6;
    targetIp[9] = 0x1f;
    targetIp[10] = 0x72;
    targetIp[11] = 0xff;
    targetIp[12] = 0xfe;
    targetIp[13] = 0xf5;
    targetIp[14] = 0x90;
    targetIp[15] = 0x50;
}



int main()
{
  setupTeste();
  //readTargetMacAndIP();


  //printf("%c\n", targetMac[0]);
  //printf("%c\n", targetIp[0]);

  int i, sockFd = 0, retValue = 0;
  char buffer[BUFFER_LEN], dummyBuf[50];
  //struct sockaddr_ll destAddr;

  etherType = htons(0x86DD);

  //signal(SIGINT, intHandler);

/* Criacao do socket. Todos os pacotes devem ser construidos a partir do protocolo Ethernet. */
  /* De um "man" para ver os parametros.*/
  /* htons: converte um short (2-byte) integer para standard network byte order. */
  /*if((sockFd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
  {
    printf("Erro na criacao do socket.\n");
    exit(1);
  }*/

  strcpy(interfaceName, "eth0");
  acquireMAC(&localMac);



  /* Configura MAC Origem e Destino */





  // O procedimento abaixo eh utilizado para "setar" a interface em modo promiscuo
  /*strcpy(ifr.ifr_name, interfaceName);
  if(ioctl(sockFd, SIOCGIFINDEX, &ifr) < 0)
      printf("erro no ioctl!");
  ioctl(sockFd, SIOCGIFFLAGS, &ifr);
  ifr.ifr_flags |= IFF_PROMISC;
  ioctl(sockFd, SIOCSIFFLAGS, &ifr);*/

  /* Identificacao de qual maquina (MAC) deve receber a mensagem enviada no socket. */
  destAddr.sll_family = htons(PF_PACKET);
  destAddr.sll_protocol = htons(ETH_P_ALL);
  destAddr.sll_halen = 6;
  destAddr.sll_ifindex = 2;

  //tcpconnect();
  tcphalfopening();
  //stealthscan();


   /* indice da interface pela qual os pacotes serao enviados. Eh necessário conferir este valor. */
  /*
  while(1)
    {
        recv(sockFd,(char *) &buff1, sizeof(buff1), 0x0);
        if (buff1[12] == 0x08 && buff1[13] == 0x06)
        {
            if (buff1[20] == 0x00 && buff1[21] == 0x01)
            {

                if(!(buff1[6] == localMac[0] && buff1[7] == localMac[1] && buff1[8] == localMac[2] && buff1[9] == localMac[3] && buff1[10] == localMac[4] && buff1[11] == localMac[5]))//if(!memcmp(&buff1[6], localMac, sizeof(unsigned char) * 6))
                {
                    memcpy(&ethHeader, &buff1[0], 14 * sizeof(uint8_t));
                    memcpy(&arpHeader, &buff1[14], 8 * sizeof(uint8_t));
                    memcpy(&targetMac, &ethHeader.ether_shost, 6 * sizeof(uint8_t));

                    break;
                }
            }
        }
       }

    memcpy(&buff3, &buff1, sizeof(buff1));


    memcpy(&destAddr.sll_addr, &ethHeader.ether_shost, 6);

    //Copiamos o header ethernet forjado para o buffer
    memcpy(&buff2[6], &localMac, sizeof(uint8_t) * 6); //SOURCE HARDWARE ADDRESS = LOCAL MAC
    memcpy(buff2, &ethHeader.ether_shost, sizeof(uint8_t) * 6); //RECEIVER HARDWARE ADDRESS = TARGETMAC
    memcpy(&buff2[12], &ethHeader.ether_type, sizeof(uint16_t)); //TIPO CONTINUA O MESMO (ARP)
    //Terminamos de forjar o ethernet

    //COMECAMOS A FORJAR O ARP
    memcpy(&buff2[14], &buff1[14], BUFFSIZE - sizeof(char) * 8); //COPIAMOS OS PRIMEIROS 8 BYTES DO CABECALHO ARP
    buff2[21] = 0x02; //ALTERAMOS DE ARP REQUEST PARA ARP REPLY
    memcpy(&buff2[22], &localMac, sizeof(char) * 6); //SOURCE HARDWARE ADDRESS = LOCAL MAC
    memcpy(&buff2[28], &buff1[38], sizeof(char) * 4); //SOURCE PROTOCOL ADDRESS = IP DO HOST COM MAC QUE ELE BUSCAVA
    memcpy(&buff2[32], &ethHeader.ether_shost, sizeof(char) * 6); //TARGET HARDWARE ADDRESS = TARGET MAC
    memcpy(&buff2[38], &buff1[28], sizeof(char) * 4); //TARGET PROTOCOL ADDRESS = IP DO ALVO

  while(keepRunning) {
    /* Envia pacotes de 42 bytes */

    /*if((retValue = sendto(sockFd, buff2, 42, 0, (struct sockaddr *)&(destAddr), sizeof(struct sockaddr_ll))) < 0) {
       printf("ERROR! sendto() \n");
       exit(1);
    }


    if(buff1[6] == localMac[0] && buff1[7] == localMac[1] && buff1[8] == localMac[2] && buff1[9] == localMac[3] && buff1[10] == localMac[4] && buff1[11] == localMac[5])
    {
      if(buff1[0] == targetMac[0] && buff1[1] == targetMac[1] && buff1[2] == targetMac[2] && buff1[3] == targetMac[3] && buff1[4] == targetMac[4] && buff1[5] == targetMac[5])
        printf("Pacote Capturado\n");
    }
    //printf("Enviando pacote ARP Reply para alvo\n");
  }

  printf("Reconstruindo tabela ARP do alvo\n");

  memcpy(&destAddr.sll_addr, &ethHeader.ether_dhost, 6);
  if((retValue = sendto(sockFd, buff3, 42, 0, (struct sockaddr *)&(destAddr), sizeof(struct sockaddr_ll))) < 0) {
       printf("ERROR! sendto() \n");
       exit(1);
    }*/
}
