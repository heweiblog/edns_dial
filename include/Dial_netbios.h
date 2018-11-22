#ifndef _DIAL_NETBIOS_H_
#define _DIAL_NETBIOS_H_


typedef struct netbiosHeader
{

		unsigned char type; // Type of the packet

		unsigned char flags; // Flags

		unsigned short length; // Count of data bytes (netbios header not included)

} netbioshdr_t;


typedef struct  {

		unsigned char protocol[4];               // Contains 0xFF,'SMB'

		unsigned char command;                // Command code

		union {

				struct {

						unsigned char errorclass;         // Error class

						unsigned char reserved;           // Reserved for future use

						unsigned short error;             // Error code

				} doserror;

				unsigned int status;                 // 32-bit error code

		} status;

		unsigned char flags;                     // Flags

		unsigned short flags2;                   // More flags

		union {

				unsigned short pad[6];               // Ensure section is 12 bytes long

				struct {

						unsigned shortpidhigh;           // High part of PID

						unsigned int unused;            // Not used

						unsigned int unused2;

				} extra;

		};

		unsigned short tid;                      // Tree identifier

		unsigned short pid;                      // Caller's process id

		unsigned short uid;                      // Unauthenticated user id

		unsigned short mid;                      // multiplex id

} smbhdr_t;


int generate_netbios_packet(unsigned char *pnetbios_buf,int buf_size);



#endif
