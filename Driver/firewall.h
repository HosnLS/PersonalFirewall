#ifndef FIREWALL_H
#define FIREWALL_H

#include "ntdef.h"

// ReSharper disable IdentifierTypo
// ReSharper disable CommentTypo
// ReSharper disable CppInconsistentNaming
// #pragma once

#define RULE_MAX_LENGTH 16
#define NAME_MAX_LENGTH 64

#define PFW_RULE_NUMBER 10
#define PFW_ALLOCATE_TAG 'pfw1'
#define PFW_PROFILE_LOCATION L"\\DosDevices\\C:\\PotionFirewall.bin"

typedef enum {
	Any = 0,
	ARP,
	IPv4,
	IPv6,
	ICMP,
	IPSec,
	TCP,
	UDP,
	L2TP,	// No
	//PPP,	// No
	//DNS,	// No
	//HTTP,	// No
	//FTP,	// No
	//SMTP,	// No
	//Telnet	// No
} Protocol;
typedef enum {
	In = 1 << 0,
	Out = 1 << 1,
	InOut = In | Out
} Direction;
typedef struct {
	UCHAR mac[6];
	UCHAR mask[6];
} MacRule;
typedef struct {
	UCHAR version;
	UCHAR ip[16];
	UCHAR mask[16];
} IpRule;
typedef struct {
	USHORT startPort;
	USHORT endPort;
} PortRule;
//typedef struct {
//	UCHAR length;
//	UCHAR pattern[PAYLOAD_PATTERN_MAX_LENGTH];
//	UCHAR mask[PAYLOAD_PATTERN_MAX_LENGTH];
//} PayloadRule;
typedef struct {
	ULONG id;
	UCHAR name[NAME_MAX_LENGTH];
	Direction direction;
	Protocol protocol;
	MacRule srcMacs, dstMacs;
	IpRule srcIps, dstIps;
	PortRule srcPorts, dstPorts;
	//PayloadRule payloads[RULE_MAX_LENGTH];
} FirewallRule;
typedef struct {
	UCHAR Present;
	UCHAR Enabled;
	ULONGLONG Statistic;
	FirewallRule Rule;
} FirewallEntry;

//typedef struct {
//	UCHAR Flag;
//	UCHAR Address;
//	UCHAR Context;
//	USHORT Protocal;
//	// 0x0021 IP
//} PPP_HEADER;
typedef struct {
	UCHAR DstMac[6];
	UCHAR SrcMac[6];
	USHORT EthType;
	// 0x0800 IPv4		0x0806 ARP		0x86DD IPv6		
} ETHERNET_HEADER;
//typedef struct {
//	// T L _ _ S _ O P _ _ _ _ Version
//	USHORT FlagsAndVersion;
//	USHORT TotalLength;		// Bytes
//	USHORT TunnelId;
//	USHORT SessionId;
//	USHORT NumberSender;
//	USHORT NumberReceiver;
//	USHORT OffsetSize;
//	USHORT OffsetPad;
//} L2TP_HEADER;
typedef struct {
	// UCHAR Version		: 4
	// UCHAR HeaderLength	: 4     4 Bytes
	UCHAR VH;
	UCHAR TypeOfService;
	USHORT TotalLength;		// Bytes
	USHORT Identifier;
	USHORT FFO;
	UCHAR TTL;
	UCHAR Protocol;
	// 1 ICMP	6 TCP	17 UDP	50 ESP	51 AH
	USHORT HeaderChecksum;
	UCHAR SrcAddr[4];
	UCHAR DstAddr[4];
} IPV4_HEADER;
typedef struct {
	// UCHAR Version : 4;
	// UCHAR TrafficClass : 8
	// UCHAR FLowLable : 20
	ULONG VTF;
	USHORT PayloadLength;	// Bytes
	UCHAR Protocol;
	// 6 TCP	17 UDP	50 ESP	51 AH	58 IPv6-ICMP
	UCHAR HopLimit;
	UCHAR SrcAddr[16];
	UCHAR DstAddr[16];
} IPV6_HEADER;
typedef struct {
	USHORT HardwareType;	// Ethernet 0x0001
	USHORT Protocal;
	UCHAR HardwareLength;			// Mac 6
	UCHAR ProtocalLength;			// IPv4 4
	USHORT Opcode;
	UCHAR SHA[6];
	UCHAR SPA[4];
	UCHAR DHA[6];
	UCHAR DPA[4];
} ARP_HEADER;
typedef struct {
	USHORT SrcPort;
	USHORT DstPort;
	ULONG Seq;
	ULONG Ack;
	// HeaderLength 4		4 Bytes
	// Resv 3
	// Flags 9
	USHORT HRF;
	USHORT Win;
	USHORT Checksum;
	USHORT Urgent;
} TCP_HEADER;
typedef struct {
	USHORT SrcPort;
	USHORT DstPort;
	USHORT TotalLength;		//Bytes
	USHORT Checksum;
} UDP_HEADER;

FirewallEntry FWEntryTable[RULE_MAX_LENGTH];

#endif