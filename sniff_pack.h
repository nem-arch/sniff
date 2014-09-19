#include <iostream>
#include <stdio.h>

#define OUT_RAW	 0x0
#define OUT_NICE 0x1
#define OUT_DUMP 0x2
#define OUT_TRPT 0x3
unsigned char outlevel = OUT_NICE;
std::string out;
void hexdump(void *ptr, int buflen, char *out);
void oraw();
void nice();

#define ETH_IPV4 0x0800
#define ETH_ARP  0x0806
#define ETH_IPV6 0x86DD
#define ETH_RARP 0x8035 // reverse address resolution protocol
#define ETH_VLAN 0x8100
#define ETH_POED 0x8863 // pppoe discovery
#define ETH_POES 0x8864 // pppoe session

char IP_NAMES[143][16] = {
	//----------------
	"HOPOPT",
	"ICMP",
	"IGMP",
	"GGP",
	"IPv4",
	"ST",
	"TCP",
	"CBT",
	"EGP",
	"IGP",
	"BBN-RCC-MON",
	"NVP-II",
	"PUP",
	"ARGUS",
	"EMCON",
	"XNET",
	"CHAOS",
	"UDP",
	"MUX",
	"DCN-MEAS",
	"HMP",
	"PRM",
	"XNS-IDP",
	"TRUNK-1",
	"TRUNK-2",
	"LEAF-1",
	"LEAF-2",
	"RDP",
	"IRTP",
	"ISO-TP4",
	"NETBLT",
	"MFE-NSP",
	"MERIT-INP",
	"DCCP",
	"3PC",
	"IDPR",
	"XTP",
	"DDP",
	"IDPR-CMTP",
	"TP++",
	"IL",
	"IPv6",
	"SDRP",
	"IPv6-Route",
	"IPv6-Frag",
	"IDRP",
	"RSVP",
	"GRE",
	"DSR",
	"BNA",
	"ESP",
	"AH",
	"I-NLSP",
	"SWIPE",
	"NARP",
	"MOBILE",
	"TLSP",
	"SKIP",
	"IPv6-ICMP",
	"IPv6-NoNxt",
	"IPv6-Opts",
	"HOST_INTERNAL",
	"CFTP",
	"LOCAL_NETWORK",
	"SAT-EXPAK",
	"KRYPTOLAN",
	"RVD",
	"IPPC",
	"DISTRIB_FS",
	"SAT-MON",
	"VISA",
	"IPCV",
	"CPNX",
	"CPHB",
	"WSN",
	"PVP",
	"BR-SAT-MON",
	"SUN-ND",
	"WB-MON",
	"WB-EXPAK",
	"ISO-IP",
	"VMTP",
	"SECURE-VMTP",
	"VINES",
	"TTP/IPTM",
	"NSFNET-IGP",
	"DGP",
	"TCF",
	"EIGRP",
	"OSPFIGP",
	"Sprite-RPC",
	"LARP",
	"MTP",
	"AX.25",
	"IPIP",
	"MICP",
	"SCC-SP",
	"ETHERIP",
	"ENCAP",
	"PRIV_CRYPT_SC",
	"GMTP",
	"IFMP",
	"PNNI",
	"PIM",
	"ARIS",
	"SCPS",
	"QNX",
	"A/N",
	"IPComp",
	"SNP",
	"Compaq-Peer",
	"IPX-in-IP",
	"VRRP",
	"PGM",
	"ZERO_HOP_PROT",
	"L2TP",
	"DDX",
	"IATP",
	"STP",
	"SRP",
	"UTI",
	"SMP",
	"SM",
	"PTP",
	"ISIS over IPv4",
	"FIRE",
	"CRTP",
	"CRUDP",
	"SSCOPMCE",
	"IPLT",
	"SPS",
	"PIPE",
	"SCTP",
	"FC",
	"RSVP-E2E-IGNORE",
	"Mobility Header",
	"UDPLite",
	"MPLS-in-IP",
	"manet",
	"HIP",
	"Shim6",
	"WESP",
	"ROHC"
};

#define IPV6_HOPOPT	0

#define IPV4_ICMP	1
#define IPV4_ENCAP	4
#define IPV4_TCP	6
#define IPV4_UDP	17

#define IPV6_ENCAP	41
#define IPV6_ROUTE	43
#define IPV6_FRAG	44
#define IPV6_ICMP	58
#define IPV6_NONEXT	59
#define IPV6_OPTS	60

struct _tcph {
	unsigned short src_port;
	unsigned short dst_port;
	unsigned int seq;
	unsigned int ack;
	unsigned char offset;
	unsigned char flags;
	unsigned short winsize;
	unsigned short checksum;
	unsigned short urg;
} tcph;
void tcp_unpack(unsigned char* buf, ssize_t buflen)
{
	memset(&tcph, 0, sizeof(tcph));
	memcpy(&tcph, buf, sizeof(tcph));
	buf += sizeof(tcph);
	buflen -= sizeof(tcph);
	std::string s;
	char tmp[256];
	switch (outlevel) {
		case OUT_RAW:
			break;
		case OUT_NICE:
			s.append("      ");
			s.append("TCP");
			s.append("  ");
			sprintf(tmp, "Src.Port: %u  Dst.Port: %u  Seq: %u  Ack: %u  Offset: %u\n",\
					ntohs(tcph.src_port), ntohs(tcph.dst_port), ntohl(tcph.seq), ntohl(tcph.ack), (tcph.offset>>4)*4);
			s.append(tmp);
			s.append("           ");
			sprintf(tmp, "NS: %u  CWR: %u  ECE: %u  URG: %u  ACK: %u  PSH: %u  RST: %u  SYN: %u  FIN: %u\n\0",\
					(tcph.offset)&1, (tcph.flags>>7)&1, (tcph.flags>>6)&1, (tcph.flags>>5)&1, (tcph.flags>>4)&1,\
					(tcph.flags>>3)&1, (tcph.flags>>2)&1, (tcph.flags>>1)&1, (tcph.flags)&1);
			s.append(tmp);
			out.insert(0, s);
			break;
		case OUT_DUMP:
			break;
		case OUT_TRPT:
			break;
		default:
			break;
	}
}

struct _icmph {
	unsigned char type;
	unsigned char code;
	unsigned short checksum;
} icmph;
void icmp_unpack(unsigned char* buf, ssize_t buflen)
{
	memset(&icmph, 0, sizeof(icmph));
	memcpy(&icmph, buf, sizeof(icmph));
	buf += sizeof(icmph);
	buflen -= sizeof(icmph);
	std::string s;
	char tmp[256];
	switch (outlevel) {
		case OUT_RAW:
			break;
		case OUT_NICE:
			s.append("      ");
			s.append("ICMP");
			s.append("  ");
			sprintf(tmp, "Type: %u  Code: %u\n", icmph.type, icmph.code);
			s.append(tmp);
			out.insert(0, s);
			break;
		case OUT_DUMP:
			break;
		case OUT_TRPT:
			break;
		default:
			break;
	}
}

struct _udph {
	unsigned short src_port;
	unsigned short dst_port;
	unsigned short length;
	unsigned short checksum;
} udph;
void udp_unpack(unsigned char* buf, ssize_t buflen)
{
	memset(&udph, 0, sizeof(udph));
	memcpy(&udph, buf, sizeof(udph));
	buf += sizeof(udph);
	buflen -= sizeof(udph);
	std::string s;
	char tmp[256];
	switch (outlevel) {
		case OUT_RAW:
			break;
		case OUT_NICE:
			s.append("      ");
			s.append("UDP");
			s.append("  ");
			sprintf(tmp, "Src.Port: %u  Dst.Port %u  Len: %u\n", ntohs(udph.src_port), ntohs(udph.dst_port), ntohs(udph.length));
			s.append(tmp);
			out.insert(0, s);
			break;
		case OUT_DUMP:
			break;
		case OUT_TRPT:
			break;
		default:
			break;
	}
}

struct _ip4h {
	unsigned char version_ihl;
	unsigned char dscp_ecn;
	unsigned short length;
	unsigned short id;
	unsigned short flag_fragmentoffset;
	unsigned char ttl;
	unsigned char protocol;
	unsigned short checksum;
	unsigned char src_ip[4];
	unsigned char dst_ip[4];
} ip4h;
void ip4_unpack(unsigned char* buf, ssize_t buflen)
{
	memset(&ip4h, 0, sizeof(ip4h));
	memcpy(&ip4h, buf, sizeof(ip4h));
	buf += sizeof(ip4h);
	buflen -= sizeof(ip4h);
	switch (ip4h.protocol) {
		case IPV4_TCP:
			tcp_unpack(buf, buflen);
			break;
		case IPV4_ICMP:
			icmp_unpack(buf, buflen);
			break;
		case IPV4_UDP:
			udp_unpack(buf, buflen);
			break;
		case IPV4_ENCAP:
			break;
		default:
			break;
	}
	std::string s;
	char tmp[256];
	char srcip[17], dstip[17];
	switch (outlevel) {
		case OUT_RAW:
			break;
		case OUT_NICE:
			s.append("      ");
			s.append("IPv4 (");
			if (ip4h.protocol<143) s.append(IP_NAMES[ip4h.protocol]);
			else {
				sprintf(tmp, "0x%.4X", ip4h.protocol);
				s.append(tmp);
			}
			s.append(")  ");
			snprintf(srcip,16,"%u.%u.%u.%u",
				ip4h.src_ip[0],ip4h.src_ip[1],ip4h.src_ip[2],ip4h.src_ip[3]);
			snprintf(dstip,16,"%u.%u.%u.%u",
				ip4h.dst_ip[0],ip4h.dst_ip[1],ip4h.dst_ip[2],ip4h.dst_ip[3]);
			sprintf(tmp, "Scr.IP: %s  Dst.IP: %s  Len: %u  TTL: %u", srcip, dstip, ntohs(ip4h.length), ip4h.ttl);
			s.append(tmp);
			s.append("\n");
			out.insert(0, s);
			break;
		case OUT_DUMP:
			break;
		case OUT_TRPT:
			break;
		default:
			break;
	}
}

struct _ip6h {
	unsigned int version_class_flow;
	unsigned short length;
	unsigned char next;
	unsigned char hoplimit;
	unsigned char src_ip[16];
	unsigned char dst_ip[16];
} ip6h;
void ip6_unpack(unsigned char* buf, ssize_t buflen)
{
	memset(&ip6h, 0, sizeof(ip6h));
	memcpy(&ip6h, buf, sizeof(ip6h));
	buf += sizeof(ip6h);
	buflen -= sizeof(ip6h);
	switch (outlevel) {
		case OUT_RAW:
			break;
		case OUT_NICE:
			break;
		case OUT_DUMP:
			break;
		case OUT_TRPT:
			break;
		default:
			break;
	}
}

struct _arph {
	unsigned short htype;
	unsigned short ptype;
	unsigned char len_mac;
	unsigned char len_ip;
	unsigned short op;
	unsigned char src_mac[6];
	unsigned char src_ip[4];
	unsigned char dst_mac[6];
	unsigned char dst_ip[4];
} arph;
void arp_unpack(unsigned char* buf, ssize_t buflen)
{
	memset(&arph, 0, sizeof(arph));
	memcpy(&arph, buf, sizeof(arph));
	std::string s;
	char tmp[256];
	char srcmac[19], dstmac[19], srcip[17], dstip[17];
	snprintf(srcmac,18,"%.2X:%.2X:%.2X:%.2X:%.2X:%.2X", \
		arph.src_mac[0],arph.src_mac[1],arph.src_mac[2],arph.src_mac[3],arph.src_mac[4],arph.src_mac[5]);
	snprintf(dstmac,18,"%.2X:%.2X:%.2X:%.2X:%.2X:%.2X", \
		arph.dst_mac[0],arph.dst_mac[1],arph.dst_mac[2],arph.dst_mac[3],arph.dst_mac[4],arph.dst_mac[5]);
	snprintf(srcip,16,"%u.%u.%u.%u",
		arph.src_ip[0],arph.src_ip[1],arph.src_ip[2],arph.src_ip[3]);
	snprintf(dstip,16,"%u.%u.%u.%u",
		arph.dst_ip[0],arph.dst_ip[1],arph.dst_ip[2],arph.dst_ip[3]);
	switch (outlevel) {
		case OUT_RAW:
			break;
		case OUT_NICE:
			s.append("      ");
			s.append("ARP");
			s.append("  ");
			sprintf(tmp, "HType: %u  PType: 0x%.4X  Op: %i\n           Src.MAC: %s  Src.IP: %s\n           Dst.MAC: %s  Dst.IP: %s\n", \
					ntohs(arph.htype), ntohs(arph.ptype), ntohs(arph.op), srcmac, srcip, dstmac, dstip);
			s.append(tmp);
			out.insert(0, s);
			break;
		case OUT_DUMP:
			break;
		case OUT_TRPT:
			break;
		default:
			break;
	}
}

struct _ethh {
	unsigned char src_mac[6];
	unsigned char dst_mac[6];
	unsigned short protocol;
} ethh;
void eth_unpack(unsigned char* buf, ssize_t buflen)
{
	out = "\n\n";
	memset(&ethh, 0, sizeof(ethh));
	memcpy(&ethh, buf, sizeof(ethh));
	buf += sizeof(ethh);
	buflen -= sizeof(ethh);
	switch (ntohs(ethh.protocol)) {
		case ETH_IPV4:
			ip4_unpack(buf, buflen);
			break;
		case ETH_IPV6:
			ip6_unpack(buf, buflen);
			break;
		case ETH_ARP:
			arp_unpack(buf, buflen);
			break;
		case ETH_RARP:
			break;
		case ETH_VLAN:
			break;
		case ETH_POED:
			break;
		case ETH_POES:
			break;
		default:
			break;
	}
	char tmp[32];
	char dmp[2048];
	std::string s;
	switch (outlevel) {
		case OUT_RAW:
			hexdump(buf, buflen, dmp);
			s.append(dmp);
			out.insert(0, s);
			break;
		case OUT_NICE:
			s.append("ETH   ");
			sprintf(tmp,"SRC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X", \
					ethh.src_mac[0],ethh.src_mac[1],ethh.src_mac[2],ethh.src_mac[3],ethh.src_mac[4],ethh.src_mac[5]);
			s.append(tmp);
			s.append("  ");
			sprintf(tmp,"DST: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X", \
					ethh.dst_mac[0],ethh.dst_mac[1],ethh.dst_mac[2],ethh.dst_mac[3],ethh.dst_mac[4],ethh.dst_mac[5]);
			s.append(tmp);
			s.append(" \n");
			out.insert(0, s);
			break;
		case OUT_DUMP:
			break;
		case OUT_TRPT:
			break;
		default:
			break;
	}
	std::cout << out;
}

/* output helpers */

void hexdump(void *ptr, int buflen, char *out)
{
	unsigned char* buf = (unsigned char*)ptr;
	int i, j;
	for (i=0; i<buflen; i+=16)
	{
		sprintf(out,"%.4X  ", i);
		out+=6;
		for (j=0; j<16; j++)
		{
			if (i+j < buflen)
				sprintf(out,"%.2X ", buf[i+j]);
			else
				sprintf(out,"   ");
			out+=3;
		}
		sprintf(out++,"  ");
		out++;
		for (j=0; j<16; j++)
		{
			if (i+j < buflen)
				sprintf(out++,"%c", isprint(buf[i+j]) ? buf[i+j] : '.');
		}
		sprintf(out++,"\n");
	}
}
