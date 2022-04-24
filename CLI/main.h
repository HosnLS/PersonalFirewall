typedef unsigned char UCHAR;
typedef char CHAR;
typedef unsigned short USHORT;
typedef short SHORT;
typedef unsigned long ULONG;
typedef long LONG;
typedef unsigned long long ULONGLONG;
typedef long long  LONGLONG;

#define RULE_MAX_LENGTH 16
#define NAME_MAX_LENGTH 64

typedef enum {
	In = 1 << 0,
	Out = 1 << 1,
	InOut = In | Out
} Direction;
const char* ProtocalName[] = { "Any", "ARP", "IPv4", "IPv6", "ICMP", "IPSec", "TCP", "UDP" };
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
FirewallEntry FWEntryTable[RULE_MAX_LENGTH];