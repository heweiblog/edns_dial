namespace c_glib dnsrpc
namespace java rpc.yamutech.com
namespace cpp rpc.yamutech.com
namespace * rpc.yamutech.com

exception Xception {
  1: i32 errorCode,
  2: string message
}

typedef string ObjectId 

enum ModuleType
{
  CRM = 1,
  DIALING =2,
  YRDNS = 3
}

enum LogLevel
{
  NORMAL = 0,
  WARN,
  ERROR
}

enum DialStatus
{
  OK = 0,
  FAIL
}

enum RetCode
{
  OK = 0, 
  FAIL 
}



enum SecParamName
{
  SEC_PARAM_WHITELIST = 0,
  SEC_PARAM_ACL, 
  SEC_PARAM_QPSLIMIT, 
  SEC_PARAM_BLACKLIST, 
  SEC_PARAM_TCP, 
  SEC_PARAM_TCPLIMIT,
  SEC_PARAM_ICMPLIMIT,
  SEC_PARAM_CACHEVIRUSLIMIT,
  SEC_PARAM_FILTERIP,
  SEC_PARAM_FILTERUDP,
  SEC_PARAM_FILTERDNS,
  SEC_PARAM_DDOSDEFEND,
  SEC_PARAM_DNSFLOODDEFND  
}

enum DnsParamName
{
  DNS_PARAM_AUTH = 0, 
  DNS_PARAM_XFORWARD,
  DNS_PARAM_TTL,
  DNS_PARAM_REDIRECT,
  DNS_PARAM_SPREAD,
  DNS_PARAM_RECUSIVE,
  DNS_PARAM_CACHE
}

enum Status
{
  STATUS_INACTIVE = 0,
  STATUS_ACTIVE = 1
}

enum DialMethod
{
  DIAL_TCPPORT = 0, 
  DIAL_IMCP,
  DIAL_HTTPGET,
  DIAL_DATABASE,
  DIAL_EXTHTTPGET
}

enum AlarmStatus
{
  ALARM_OFF = 0,
  ALARM_ON
}

enum AlarmType
{
  DNSysDeviceQpsOverAlarm = 0, 
  DNSysDeviceRequestIpOverAlarm=1,
  DNSysDeviceDomainQpsOverAlarm=2,
  DNSysDeviceDnameQpsOverAlarm=3,
  DNSysDeviceFocusDomainAlarm=4,
  DeviceCpuUsageAlarm=5,
  DeviceMemoryUsageAlarm=6,
  DevicePartitionUsageAlarm= 7,
  DeviceNicFlowOverAlarm=8,
  NoneDeviceConnectionAlarm= 9,
  DeviceProcessAlarm=10,
  DNSysDeviceServfailOverAlarm=11,
  ForwardFailAlarm=12,
  ProxyFailAlarm=13,
  ServiceFailAlarm=14,
  DiskFailAlarm=15,
  LogAlarm=16,
  RecordialFailAlarm=17,
  RedirectFailAlarm=18,
  NginxServerFailAlarm=19,
  DhcpPoolAlarm=20,
  DhcpIpAddressConflictsAlarm=21,
  DhcpQpsAlarm=22,
  DhcpIlegalServerAlarm=23,
  DDNSAlarm=24,
  HostHaAlarm=25
}

enum ModuleState
{
  STARTUP=0,
  REGISTERED
}

enum SysCommand
{
  RestoreConfig = 0
}

enum DialServerType
{
  XPROXY=0,
  REDIRECT,
  XFORWARD
}

struct RetRecord
{
  1: string recordId,
  2: RetCode code
}

struct IpAddr
{
  1: i32 version,
  2: string addr  
}

struct DialNginxServer
{
  1: string localURL,
  2: i32 priority
}

struct DialRecordStatus 
{
  1: ObjectId rid,
  2: DialStatus status,
  3: i64 delay}

struct DialNginxStatus
{
  1: DialNginxServer server,
  2: DialStatus status,
  3: i64 delay}

struct DialRecordAlarm
{
  1: IpAddr ip,
  2: bool enable,
  3: bool dial
}
struct DialServerStatus
{
  1: ObjectId rid,
  2: IpAddr ip,
  3: DialStatus status,
  4: i64 delay}

struct IpsecAddress
{
  1: IpAddr ip,
  2: i32 mask
}

struct DomainInfo
{
  1: string typ, 
  2: string name
} 

struct RangeInfo
{
  1: i16 start,
  2: i16 ends
}

struct SysIpSec
{
  1: string name, 
  2: IpsecAddress ipsec,
  3: string recordId
}


struct AclInfo 
{
  1: ObjectId id,
  2: optional i32 priority,
  3: optional IpsecAddress srcIpSec,
  4: optional IpsecAddress dstIpSec,
  5: optional RangeInfo srcPortSec,
  6: optional RangeInfo dstPortSec,
  7: optional RangeInfo frameTypeSec,
  8: optional RangeInfo ipProtoSec,
  9: optional i32 qpsLimit  
}

struct ZoneInfo
{
  1: string name, 
  2: string viewName, 
  3: optional i32 typ,
  4: optional string nsRecord,
  5: optional string aRecord,
  6: optional string soaName,
  7: optional string soaHost,
  8: optional i32 serial,
  9: optional i32 refresh,
  10: optional i32 retries,
  11: optional i32 expire,
  12: optional i32 minTtl,
  13: string recordId
}

struct DnsQueryResultSRV
{
  1: i16 priority, 
  2: i16 weight,
  3: i16 port,
  4: string target
}

struct DnsQueryResultNAPTR
{
  1: i16 order, 
  2: i16 pref,
  3: string flags,
  4: string svc,
  5: string regexp,
  6: string domainName
}

struct DnsQueryResultMX
{
  1: i16 pref,
  2: string domainName
}

union DnsQueryResult
{
  1: string a;
  2: string aaaa,
  3: string ns,
  4: string cname,
  5: string ptr,
  6: string txt,
  7: string dname,
  8: DnsQueryResultSRV srv,
  9: DnsQueryResultNAPTR naptr,
  10: DnsQueryResultMX mx
}

enum RecordType
{
	A = 0,
	AAAA,
	NS,
	CNAME,
	PTR,
	TXT,
	SRV,
	NAPTR,
	MX
}

struct RecordInfo
{
  1: string name, 
  2: string viewName, 
  3: string zoneName,
  4: i32 typ,
  5: DnsQueryResult result,
  6: optional i32 ttl,
  7: optional i32 weight,
  8: optional Status status,
  9: string recordId,
  10: i32 dispatchStatus
}

struct ProxyServer
{
  1: IpAddr ip,
  2: i32 weight,
  3: Status status
}

struct RecurForwardPolicyInfo
{
  1: string viewName,
  2: DomainInfo domain, 
  3: optional string serverGroupName,
  4: i32 type,
  5: i32 esc_zone
}

struct ProxyPolicyInfo
{
  1: string viewName,
  2: DomainInfo domain, 
  3: optional string serverGroupName
}

struct TtlPolicyInfo
{
  1: DomainInfo domain,
  2: optional i32 minTtl, 
  3: optional i32 maxTtl
}

struct ForwardPolicyInfo
{
  1: IpAddr ip, 
  2: i16 port,
  3: optional i32 weight,
  4: optional Status status
}

struct DialRecord
{
  1: ObjectId rid,
  2: IpAddr ip,
  3: i32 ttl,
  4: i32 priority,
  5: bool enabled
}

struct HealthGroupInfo
{
  1: string zoneName,
  2: string viewName,
  3: string name,
}

struct DialOption
{
  1: string destUrl,
  2: string testMethod,
  3: list<i32> expectCode,
  4: string expectMatch
}

struct HealthPolicyInfo
{
  1: string name,
  2: DialMethod method,
  3: optional i16 port,
  4: i32 freq,
  5: i32 times,
  6: i32 passed,
  7: DialOption option
}

struct FilterReportInfo
{
  1: i32 total,
  2: i32 exceptIpLimit,
  3: i32 exceptUdpLimit,
  4: i32 exceptDnsLimit,
  5: i32 ipLimit,
  6: i32 domainLimit,
  7: i32 aclLimit,
  8: i32 userWhiteLimit,
  9: i32 userBlackLimit,
  10: i32 domainBlackLimit
}

struct RequestReportInfo
{
  1: i32 total,
  2: i32 a,
  3: i32 aaaa,
  4: i32 cname,
  5: i32 ptr,
  6: i32 txt,
  7: i32 srv,
  8: i32 naptr,
  9: i32 mx,
  10: i32 soa,
  11: i32 ns,
  12: i32 any

}

struct GeneralReportInfo
{
  1: i32 total,
  2: i32 noerr,
  3: i32 servfail,
  4: i32 nxdomain,
  5: i32 refuse,
  6: i32 formerr
}

struct DNameAccessInfo
{
  1: string zoneName,
  2: string viewName,
  3: string domain,  
  4: i32 access,
  5: GeneralReportInfo rcode,
  6: RequestReportInfo qtype
}

struct XProxyReportInfo
{
  1: i32 total,
  2: i32 proxyRequest,
  3: i32 proxyAnswer,
  4: i32 proxyForwardRequest,
  5: i32 proxyForwardAnswer
}

struct XForwardReportInfo
{
  1: i32 total,
  2: i32 xforwardRequest,
  3: i32 xforwardAnswer
}

struct RecursiveReportInfo
{
  1: i32 total,
  2: i32 recursiveRequest,
  3: i32 recursiveAnswer
}

struct BackGroundReportInfo
{
  1: i32 total,
  2: i32 smartUpdate,
  3: i32 cacheUpdate,
  4: i32 limitDrop,
  5: i32 ttlExpire
}

struct TopnIpInfo
{
  1: string ip, 
  2: i32 access
}

struct TopnDomainInfo
{
  1: string domain, 
  2: i32 access
}

struct TopnDnameInfo
{
  1: string dname, 
  2: i32 access
}

struct DDosInfo
{
  1: string ip, 
  2: string domain, 
  3: i32 access
}

struct HostInfo
{
  1: i32 cpu, 
  2: i32 memory,
  3: i32 nicin,
  4: i32 nicout
}

struct HeartBeatState
{
  1:ModuleState mState,
  2:bool serverState,
}

struct IpOverAlarm
{
  1: IpAddr ip,
  2: i32 qps,
  3: AlarmStatus status
}

struct DomainOverAlarm
{
  1: string domain,
  2: i32 qps,
  3: AlarmStatus status
}

struct NginxServerAlarm
{
  1: string serverName,
  2: string localUrl,
  3: AlarmStatus status
}

struct ZoneRequestReport
{
  1: string zoneName, 
  2: string viewName, 
  3: RequestReportInfo data
}

struct ZoneAnswerReport
{
  1: string zoneName, 
  2: string viewName, 
  3: GeneralReportInfo data,
  4: RequestReportInfo qtype
}

struct XproxyReport
{
  1: string xproxy, 
  2: XProxyReportInfo data
}

struct XforwardReport
{
  1: string xforward, 
  2: XForwardReportInfo data
}

struct RedirectServerInfo
{
  1: string viewName
  2: IpAddr ip, 
  3: optional i32 weight,
  4: optional Status status
}

struct NginxProxyInfo
{
  1: string proxyDomain,
  2: i32 proxyPort,
  3: string targetIpAddr,
  4: string targetURL,
  5: string protocol
}

struct CateWeight
{
  1: i32 cate,
  2: i32 weight
}

enum DNameType
{
  DNAME_NONE = 0, 
  DNAME_WHOLE = 1, 
  DNAME_PREFIX = 2, 
  DNAME_POSTFIX = 3
}

struct DialHealthResult
{
  1: string groupName,
  2: string policyName,
  3: list<DialRecordStatus> statusList,
}

struct DialServerResult
{
  1: DialServerStatus status,
  2: DialServerType typ
}

struct DialNginxResult
{
  1: string groupName,
  2: string policyName,
  3: list<DialNginxStatus> statusList,
}

struct SnmpGroupInfo
{
  1: bool enable,
  2: string name,
  3: string community,
  4: string user,
  5: string passwd,
  6: i32 version,
  7: i32 interval,
  8: i32 port,
  9: IpAddr ip
}

struct InterfaceTraffic
{
  1: i32 index,
  2: i64 inoctets,
  3: i64 outoctets
}

struct IpMac
{
  1: i32 index,
  2: IpAddr ip,
  3: string physaddress
}

struct InterfaceInfo
{
  1: i32 index,
  2: string descr,
  3: i32 type,
  4: i32 status,
  5: i64 speed,
  6: i32 mtu,
  7: string physaddress
}

struct RouteInfo
{
  1: i32 ifindex,
  2: IpAddr destination,
  3: IpAddr gateway,
  4: IpAddr genmask,
  5: i32 type,
  6: i32 proto
}

struct SysInfo
{
  1: i32 load,
  2: i32 usercpu, 
  3: i32 syscpu, 
  4: i32 idlecpu, 
  5: i32 totalmem, 
  6: i32 freemem, 
  7: i32 buffer, 
  8: i32 cache, 
  9: i32 availmem 
}

struct ProcessInfo
{
  1: string name,
  2: bool existflag, 
  3: i32 pid,
  4: i32 cputime, 
  5: i32 usedmem
}

service Agent
{
  RetCode         registerModule(1: ModuleType typ) throws(1: Xception ex),
  RetCode         updateHealthStatus(1: list<DialHealthResult> results) throws(1: Xception ex),
  RetCode         updateServerStatus(1: list<DialServerResult> results) throws(1: Xception ex)
  RetCode         updateNginxStatus(1: list<DialNginxResult> results) throws(1: Xception ex)
  RetCode         updateSysInfo(1: string snmp,2: SysInfo sysinfo) throws(1: Xception ex)
  RetCode         updateInterfaceInfo(1: string snmp,2: list<InterfaceInfo> interfaces) throws(1: Xception ex)
  RetCode         updateInterfaceTraffic(1: string snmp,2: list<InterfaceTraffic> traffic) throws(1: Xception ex)
  RetCode         updateInterfaceIpMac(1: string snmp,2: list<IpMac> ipmac) throws(1: Xception ex)
  RetCode         updateRouteInfo(1: string snmp,2: list<RouteInfo> routeinfo) throws(1: Xception ex)
  RetCode         updateProcessInfo(1: string snmp,2: ProcessInfo processinfo) throws(1: Xception ex)
  RetCode         updateIpSecOnlineIp(1: string ipsecid,2: list<IpAddr> iplist) throws(1: Xception ex)
}

service Yrdns
{
  list<RetRecord> addSysIpSec(1: list<SysIpSec> sysIpSecs) throws(1: Xception ex),
  list<RetRecord> delSysIpSec(1: list<SysIpSec> sysIpSecs) throws(1: Xception ex),
  RetCode         addDnsView(1: string name, 2: string ipGroupName) throws(1: Xception ex),
  RetCode         delDnsView(1: string name, 2: string ipGroupName) throws(1: Xception ex),
  list<RetRecord> addDnsZone(1: list<ZoneInfo> zones) throws(1: Xception ex),
  list<RetRecord> modDnsZone(1: list<ZoneInfo> zones) throws(1: Xception ex),
  list<RetRecord> delDnsZone(1: list<ZoneInfo> zones) throws(1: Xception ex),
  list<RetRecord> addDnsRecord(1: list<RecordInfo> records) throws(1: Xception ex),
  list<RetRecord> modDnsRecord(1: list<RecordInfo> records) throws(1: Xception ex),
  list<RetRecord> delDnsRecord(1: list<RecordInfo> records) throws(1: Xception ex),
  RetCode         addRecurForwardServerGroup(1: string groupName,2: ProxyServer server) throws(1: Xception ex),
  RetCode         modRecurForwardServerGroup(1: string groupName,2: ProxyServer server) throws(1: Xception ex),
  RetCode         delRecurForwardServerGroup(1: string groupName,2: ProxyServer server) throws(1: Xception ex),
  RetCode         addRecurForwardPolicy(1: RecurForwardPolicyInfo policy) throws(1: Xception ex),
  RetCode         modRecurForwardPolicy(1: RecurForwardPolicyInfo policy) throws(1: Xception ex),
  RetCode         delRecurForwardPolicy(1: RecurForwardPolicyInfo policy) throws(1: Xception ex),
  RetCode         setDNS64Enabled(1:bool enabled) throws(1:Xception ex),
  RetCode         addDNS64Format(1:IpAddr prefix, 2:i32 pmask, 3:IpAddr suffix, 4:i32 smask) throws(1:Xception ex),
  HeartBeatState  heartBeat() throws(1: Xception ex),
  RetCode   	  setServerState(1:bool enable) throws(1: Xception ex)
}

service Crm
{
  RetCode         systemCommand(1: SysCommand cmdType) throws(1: Xception ex),
  RetCode         setAlarmThreshHold(1: AlarmType typ, 2: i32 threshHold) throws(1: Xception ex),
  list<RetRecord> addSysIpSec(1: list<SysIpSec> sysIpSecs) throws(1: Xception ex),
  list<RetRecord> delSysIpSec(1: list<SysIpSec> sysIpSecs) throws(1: Xception ex),
  RetCode         setSecConfig(1: SecParamName name, 2: bool allowed, 3: i32 value) throws(1: Xception ex),
  RetCode         addSecWhiteList(1: string name) throws(1: Xception ex),
  RetCode         delSecWhiteList(1: string name) throws(1: Xception ex),
  RetCode         addSecIpQpsLimit(1: IpsecAddress ipsec, 2: i32 qps) throws(1: Xception ex),
  RetCode         modSecIpQpsLimit(1: IpsecAddress ipsec, 2: i32 qps) throws(1: Xception ex),
  RetCode         delSecIpQpsLimit(1: IpsecAddress ipsec) throws(1: Xception ex),
  RetCode         addSecDomainQpsLimit(1: DomainInfo domain, 2: i32 qps) throws(1: Xception ex),
  RetCode         modSecDomainQpsLimit(1: DomainInfo domain, 2: i32 qps) throws(1: Xception ex),
  RetCode         delSecDomainQpsLimit(1: DomainInfo domain) throws(1: Xception ex),
  RetCode         addSecIpBlackList(1: IpsecAddress ipsec) throws(1: Xception ex),
  RetCode         delSecIpBlackList(1: IpsecAddress ipsec) throws(1: Xception ex),
  RetCode         addSecDomainBlackList(1: DomainInfo domain) throws(1: Xception ex),
  RetCode         delSecDomainBlackList(1: DomainInfo domain) throws(1: Xception ex),
  RetCode         addSecAcl(1: AclInfo acl) throws(1: Xception ex),
  RetCode         modSecAcl(1: AclInfo acl) throws(1: Xception ex),
  RetCode         delSecAcl(1: AclInfo acl) throws(1: Xception ex),
  RetCode         setDnsConfig(1: DnsParamName name, 2: bool allowed) throws(1: Xception ex),
  RetCode         addDnsView(1: string name, 2: string ipGroupName) throws(1: Xception ex),
  RetCode         delDnsView(1: string name, 2: string ipGroupName) throws(1: Xception ex),
  RetCode         addProxyServerGroup(1: string groupName,2: ProxyServer server) throws(1: Xception ex),
  RetCode         modProxyServerGroup(1: string groupName,2: ProxyServer server) throws(1: Xception ex),
  RetCode         delProxyServerGroup(1: string groupName,2: ProxyServer server) throws(1: Xception ex),
  RetCode         addProxyPolicy(1: ProxyPolicyInfo policy) throws(1: Xception ex),
  RetCode         modProxyPolicy(1: ProxyPolicyInfo policy) throws(1: Xception ex),
  RetCode         delProxyPolicy(1: ProxyPolicyInfo policy) throws(1: Xception ex),
  ProxyPolicyInfo getProxyPolicy(1:ProxyPolicyInfo policy) throws(1: Xception ex),
  RetCode         addTtlPolicy(1: TtlPolicyInfo policy) throws(1: Xception ex),
  RetCode         modTtlPolicy(1: TtlPolicyInfo policy) throws(1: Xception ex),
  RetCode         delTtlPolicy(1: TtlPolicyInfo policy) throws(1: Xception ex),
  RetCode         addRedirectServer(1: RedirectServerInfo server) throws(1: Xception ex),
  RetCode         modRedirectServer(1: RedirectServerInfo server) throws(1: Xception ex),
  RetCode         delRedirectServer(1: RedirectServerInfo server) throws(1: Xception ex),
  RetCode         addForwardPolicy(1: ForwardPolicyInfo policy) throws(1: Xception ex),
  RetCode         modForwardPolicy(1: ForwardPolicyInfo policy) throws(1: Xception ex),
  RetCode         delForwardPolicy(1: ForwardPolicyInfo policy) throws(1: Xception ex),
  RetCode         setSmartEchoEnabled(1:bool enabled) throws(1:Xception ex),
  RetCode         addSmartCategory(1:IpAddr ip, 2:i32 mask, 3:i32 group) throws(1:Xception ex),
  RetCode         delSmartCategory(1:IpAddr ip, 2:i32 mask, 3:i32 group) throws(1:Xception ex),
  RetCode         addSmartSrcGroup(1:IpAddr ip, 2:i32 mask, 3:i32 group) throws(1:Xception ex),
  RetCode         delSmartSrcGroup(1:IpAddr ip, 2:i32 mask) throws(1:Xception ex),
  RetCode         addSmartRatio(1:DNameType type, 2:string dname, 3:i32 srcgrp, 4:list<CateWeight> weights) throws(1: Xception ex),
  RetCode         delSmartRatio(1:DNameType type, 2:string dname, 3:i32 srcgrp) throws(1: Xception ex),
  RetCode         addSmartPrior(1:DNameType type, 2:string dname, 3:i32 srcgrp, 4:list<i32> prior) throws(1: Xception ex),
  RetCode         delSmartPrior(1:DNameType type, 2:string dname, 3:i32 srcgrp) throws(1: Xception ex),
  HeartBeatState  heartBeat() throws(1: Xception ex),
  RetCode   	  setServerState(1:bool enable) throws(1: Xception ex),
  RetCode         delSysCache(1: DomainInfo domain) throws(1: Xception ex),
  RetCode         addQtypeLimit(1: string viewName 2: i32 qtype) throws(1: Xception ex),
  RetCode         delQtypeLimit(1: string viewName 2: i32 qtype) throws(1: Xception ex),
  RetCode         setAuthCacheEnabled(1:bool enabled) throws(1:Xception ex)  
}

service Dial
{
  RetCode         systemCommand(1: SysCommand cmdType) throws(1: Xception ex),
  RetCode         addHealthGroup(1: string groupName,2: string policyName) throws(1: Xception ex),
  RetCode         delHealthGroup(1: string groupName,2: string policyName) throws(1: Xception ex),
  RetCode         addHealthRecord(1: string groupName,2:list<DialRecord> records) throws(1: Xception ex),
  RetCode         delHealthRecord(1: string groupName,2:list<DialRecord> records) throws(1: Xception ex),
  RetCode         addHealthPolicy(1: HealthPolicyInfo policy) throws(1: Xception ex),
  RetCode         modHealthPolicy(1: HealthPolicyInfo policy) throws(1: Xception ex),
  RetCode         delHealthPolicy(1: HealthPolicyInfo policy) throws(1: Xception ex),
  RetCode         dialServerConfig(1: DialServerType typ, 2: bool allowed) throws(1: Xception ex),
  RetCode         addDialServer(1:ObjectId rid, 2: IpAddr ip,3: DialServerType typ) throws(1: Xception ex),
  RetCode         delDialServer(1:ObjectId rid) throws(1: Xception ex),
  RetCode         addNginxGroup(1: string groupName,2: string policyName) throws(1:Xception ex),
  RetCode         delNginxGroup(1: string groupName,2: string policyName) throws(1:Xception ex),
  RetCode         addNginxServer(1: string groupName,2: list<DialNginxServer> servers) throws(1:Xception ex),
  RetCode         delNginxServer(1: string groupName,2: list<DialNginxServer> servers) throws(1:Xception ex),
  HeartBeatState  heartBeat() throws(1: Xception ex),
  RetCode   	  setServerState(1:bool enable) throws(1: Xception ex)
  RetCode         addSnmpGroupInfo(1: SnmpGroupInfo snmp) throws(1: Xception ex),
  RetCode         delSnmpGroupInfo(1: string snmp) throws(1: Xception ex)
  RetCode         addSnmpProcessInfo(1: string snmp,2: string processname) throws(1: Xception ex),
  RetCode         delSnmpProcessInfo(1: string snmp,2: string processname) throws(1: Xception ex),
  RetCode         addIpSec(1: SysIpSec ipsec,2: i32 interval) throws(1: Xception ex),
  RetCode         delIpSec(1: string ipsecid) throws(1: Xception ex),
}

service Flowexport
{
  RetCode         addReportZone(1:string view_name, 2:list<string> znames) throws(1:Xception ex),
  RetCode         delReportZone(1:string view_name, 2:list<string> znames) throws(1:Xception ex),
  RetCode         addReportDname(1:string view_name, 2:string zone_name, 3:list<string> dnames) throws(1:Xception ex),
  RetCode         delReportDname(1:string view_name, 2:string zone_name, 3:list<string> dnames) throws(1:Xception ex),
}

service Collect
{
  void            sendDNSysDeviceQpsOverAlarm(1: i32 qps,2: AlarmStatus status),
  void            sendDNSysDeviceRequestIpOverAlarm(1: list<IpOverAlarm> ipAlarms),
  void            sendDNSysDeviceDomainQpsOverAlarm(1: list<DomainOverAlarm> domainAlarms),
  void            sendDNSysDeviceDnameQpsOverAlarm(1: list<DomainOverAlarm> dnameAlarms),
  void            sendDNSysDeviceFocusDomainAlarm(1: string dname,2: RecordType type,3: list<string>  expResults,4: list<string> curResults,5: AlarmStatus status),
  void            sendDeviceCpuUsageAlarm(1: i32 rate,2: AlarmStatus status),
  void            sendDeviceMemoryUsageAlarm(1: i32 rate,2: AlarmStatus status),
  void            sendDevicePartitionUsageAlarm(1: i32 rate,2: AlarmStatus status),
  void            sendDeviceNicFlowOverAlarm(1: i32 nicin,2: AlarmStatus status),
  void            sendNoneDeviceConnectionAlarm(1: ObjectId devid,2: string devname,3: IpAddr devip, 4: AlarmStatus status),
  void            sendDeviceProcessAlarm(1: string processName,2: AlarmStatus status),
  void            sendDNSysDeviceServfailOverAlarm(1: i32 rate,2: AlarmStatus status),
  void            sendForwardFailAlarm(1: IpAddr server, 2: AlarmStatus status),
  void            sendProxyFailAlarm(1: IpAddr server, 2: AlarmStatus status),
  void            sendRedirectFailAlarm(1: IpAddr server, 2: AlarmStatus status),
  void            sendServiceFailAlarm(1: AlarmStatus status),
  void            sendDiskFailAlarm(1: AlarmStatus status),
  void            sendNginxServerFailAlarm(1: list<NginxServerAlarm> alarms),
  void            sendLogAlarm(1: LogLevel level,2: ModuleType type,3: i32 code,4: string msg),
  void            sendRecordialFailAlarm(1:HealthGroupInfo health,2:list<DialRecordAlarm> dialRecords),
  void		      sendFilterReport(1: FilterReportInfo date),
  void            sendRequestReport(1: RequestReportInfo data),
  void            sendAnswerReport(1: GeneralReportInfo data),
  void            sendZoneRequestReport(1: list<ZoneRequestReport> reports),
  void            sendTotalZoneRequestReport(1: RequestReportInfo report),
  void            sendZoneAnswerReport(1: list<ZoneAnswerReport> reports),
  void            sendTotalZoneAnswerReport(1: GeneralReportInfo report),
  void            sendDNameAnswerReport(1: list<DNameAccessInfo> reports),
  void            sendXProxyReport(1: list<XproxyReport> reports),
  void            sendXForwardReport(1: list<XforwardReport> reports),
  void            sendRecursiveReport(1: RecursiveReportInfo data),
  void            sendBackGroundReport(1: BackGroundReportInfo data),
  void            sendTopnIpReport(1: list<TopnIpInfo> data),
  void            sendTopnDomainReport(1: list<TopnDomainInfo> data),
  void            sendTopnDnameReport(1: list<TopnDomainInfo> data),
  void            sendHostReport(1: HostInfo data),
  RetCode         systemCommand(1: SysCommand cmdType) throws(1: Xception ex),
  RetCode		  devicePause(1: bool isPause) throws(1: Xception ex),
  RetCode         setAlarmThreshHold(1: AlarmType typ, 2: i32 threshHold) throws(1: Xception ex),
  RetCode         setAlarmEnabled(1: AlarmType typ, 2: bool enabled) throws(1:Xception ex),
  HeartBeatState  heartBeat() throws(1: Xception ex),
  void            sendDDosReport(1: list<DDosInfo> data)
}
