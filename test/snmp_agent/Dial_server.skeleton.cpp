
//充当客户端头文件与服务端不同
#include "Dial.h"
#include <thrift/protocol/TBinaryProtocol.h>
#include <thrift/transport/TSocket.h>
#include <thrift/transport/TTransportUtils.h>
#include <iostream>

//模拟客户端去掉server命名空间
using namespace ::apache::thrift;
using namespace ::apache::thrift::protocol;
using namespace ::apache::thrift::transport;

using boost::shared_ptr;

using namespace  ::rpc::yamutech::com;

using namespace::std;

int main(int argc, char **argv) 
{

		shared_ptr<TSocket> socket(new TSocket("127.0.0.1",9092));
		shared_ptr<TTransport> transport(new TBufferedTransport(socket));
		shared_ptr<TProtocol> protocol(new TBinaryProtocol(transport));

		DialClient client(protocol);

		//测试调用,比如给对方下发配置
		transport->open();
		RetCode::type rtn;
		SnmpGroupInfo snmp;
		snmp.enable = false;
		snmp.name = "dev92";
		snmp.community = "public";
		snmp.user = "heweiwei";
		snmp.passwd = "heweiwei123456";
		snmp.version = 3;
		snmp.interval = 10;
		snmp.ip.addr = "192.168.6.92";

		string processname = "edns_dial";

		cout<<"start"<<endl;

  		rtn = client.addSnmpGroupInfo(snmp);
		cout<<"rtn = "<<rtn<<endl;

  		rtn = client.addSnmpProcessInfo(snmp.name,processname);
		cout<<"rtn = "<<rtn<<endl;

		SysIpSec ipsec;
		ipsec.name = "local6.0";
		ipsec.ipsec.ip.addr = "192.168.6.55";
		ipsec.ipsec.mask = 24;
		ipsec.recordId = "test6.0";
  		rtn = client.addIpSec(ipsec,10);

		sleep(60);

  		rtn = client.delSnmpGroupInfo(snmp.name);
		cout<<"rtn = "<<rtn<<endl;
  		rtn = client.delSnmpProcessInfo(snmp.name,processname);
		cout<<"rtn = "<<rtn<<endl;
  		rtn = client.delIpSec(ipsec.recordId);
		cout<<"rtn = "<<rtn<<endl;
		
    	transport->close();
  		return 0;
}

