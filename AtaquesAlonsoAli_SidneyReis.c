/*-------------------------------------------------------------*/
/* Exemplo Socket Raw - envio de mensagens                     */
/*-------------------------------------------------------------*/

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

//struct arphdr arpHeader;
//struct ether_header ethHeader;

struct sockaddr_ll destAddr = {0};

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

void stealthscan()
{
  sockEnt = 0;
  sockSai = 0;

  uint16_t sorcPortNum = 3000; // exemplo
  uint16_t destPortNum = 3000; // exemplo

  if((sockSai = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
  {
    printf("Erro na criacao do socket.\n");
    exit(1);
  }

  tcp_hdr tcp;

  tcp.sourcePort = htons(sorcPortNum);
  tcp.destPort = htons(destPortNum);
  tcp.seqNumber = htons(1); //TODO: verificar se precisa alterar
  tcp.ackNumber = htons(0); //TODO: verificar se precisa alterar
  tcp.dataOffAndFlags = htons((0x6 << 12) + 0x1);
  tcp.window = htons(0xff);

  tcp.checksum = htons(0); //TODO: fazer metodo para calcular
  tcp.urgentPointer = htons(0); //TODO: avaliar
  tcp.options = 0;

  memcpy(&bufferSai[54], &tcp, sizeof(tcp_hdr));

  ip6_hdr ip6;

  ip6.firstLine = htons(0x6 << 28);
  ip6.payloadLength = htons(0); //TODO: MUDAR DEPOIS PRO VALOR CORRETO
  ip6.nextHeader = 6;
  ip6.hopLimit = 1;

  memcpy( &bufferSai[14], &ip6,8); //8 bytes = tamanho ip6 struct
  memcpy( &bufferSai[22], &localIp,16);
  memcpy(&bufferSai[38], &targetIp, 16);

  memcpy( &bufferSai, &targetMac, 6);
  memcpy( &bufferSai[6], &localMac,6);
  memcpy( &bufferSai[12], &etherType,2);

  if(sendto(sockSai, bufferSai, 42, 0, (struct sockaddr *)&(destAddr), sizeof(struct sockaddr_ll)) < 0)
  {
    printf("ERROR! sendto() \n");
    exit(1);
  }

  recv(sockEnt,(char *) &bufferEnt, sizeof(bufferEnt), 0x0);

  if(!memcmp(&bufferEnt[54], &tcp.destPort, 16) && !memcmp(&bufferEnt[70], &tcp.sourcePort, 16))
  {
    printf("source port e destination port esperados\n");
    if(bufferEnt[164]==1)
    {
      printf("\nrecebido com RST, porta esta fechada\n");
    }
    else
    {
      printf("\nrecebido sem RST, porta esta aberta\n");
    }
  }
}

void tcpconnect()
{
    sockEnt = 0;
    sockSai = 0;
    
    uint16_t sorcPortNum = 3000; // exemplo
    uint16_t destPortNum = 3000; // exemplo
    
    if((sockSai = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        printf("Erro na criacao do socket.\n");
        exit(1);
    }
    
    tcp_hdr tcp;
    
    tcp.sourcePort = htons(sorcPortNum);
    tcp.destPort = htons(destPortNum);
    tcp.seqNumber = htons(1); //TODO: verificar se precisa alterar
    tcp.ackNumber = htons(0); //TODO: verificar se precisa alterar
    tcp.dataOffAndFlags = htons((0x6 << 12) + 0x2);
    tcp.window = htons(0xff);
    
    tcp.checksum = htons(0); //TODO: fazer metodo para calcular
    tcp.urgentPointer = htons(0); //TODO: avaliar
    tcp.options = 0;
    
    memcpy( &bufferSai[54], &tcp, sizeof(tcp_hdr));

    ip6_hdr ip6;
    uint32_t tipo =0x6 << 12;
    ip6.firstLine = htons(tipo);
    ip6.payloadLength = htons(sizeof(tcp_hdr)); //????TODO: MUDAR DEPOIS PRO VALOR CORRETO?????
    ip6.nextHeader = 6;
    ip6.hopLimit = 5;


    memcpy(&bufferSai[14], &ip6,  8); //8 bytes = tamanho ip6 struct
    memcpy(&bufferSai[22],&localIp, 16);
    memcpy(&bufferSai[38], &targetIp, 16);

    memcpy(&bufferSai, &targetMac, 6);
    memcpy(&bufferSai[6], &localMac, 6);
    memcpy(&bufferSai[12], &etherType, 2);

  if(sendto(sockSai, bufferSai, 14 + sizeof(tcp_hdr) + sizeof(ip6_hdr) + 2 * 16 /*tamanho dos enderecos ipv6*/ + 80, 0, (struct sockaddr *)&(destAddr), sizeof(struct sockaddr_ll)) < 0)
  {
    printf("ERROR! sendto() \n");
    exit(1);
  }

  int i = 150000;
  while(i != 0)
  {
    if(recv(sockEnt,(char *) &bufferEnt, sizeof(bufferEnt), 0x0) != 0)
    {
        break;
    }

    i--;
  }

  if(i )


  


  printf("lol\n");
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
    targetMac[5] = 0xbe;

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
  printf("%s\n", "cara");
  
  //readTargetMacAndIP();
  setupTeste();


  printf("%c\n", targetMac[0]);
  printf("%c\n", targetIp[0]);

  int i, sockFd = 0, retValue = 0;
  char buffer[BUFFER_LEN], dummyBuf[50];
  //struct sockaddr_ll destAddr;

  etherType = htons(0x86DD);

  signal(SIGINT, intHandler);

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

  tcpconnect();
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
