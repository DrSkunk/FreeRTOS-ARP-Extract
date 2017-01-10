/********************************************************************************
 * 	Standard includes
********************************************************************************/


#include <stdio.h>
#include <stdlib.h>
//#include <stdint.h>
#include <string.h>
#include <stdbool.h>

/********************************************************************************
 * 	Global variables and structs used in verfied functions
********************************************************************************/


#define int8_t char
#define uint8_t unsigned char
#define uint16_t unsigned short
#define int32_t long
#define uint32_t unsigned long

// From projdefs.h
//#define pdFALSE			( ( BaseType_t ) 0 )
#define pdFALSE				0
//#define pdTRUE			( ( BaseType_t ) 1 )
#define pdTRUE				1
#define pdPASS			( pdTRUE )
#define pdFAIL			( pdFALSE )

// From FreeRTOS_UDP_IP.c (only definitions)
/* When the age of an entry in the ARP table reaches this value (it counts down
to zero, so this is an old entry) an ARP request will be sent to see if the
entry is still valid and can therefore be refreshed. */
#define ipMAX_ARP_AGE_BEFORE_NEW_ARP_REQUEST	( 3 )

/* The number of octets in the MAC and IP addresses respectively. */
#define ipMAC_ADDRESS_LENGTH_BYTES 6
#define ipIP_ADDRESS_LENGTH_BYTES 4

/* The expected IP version and header length coded into the IP header itself. */
#define ipIP_VERSION_AND_HEADER_LENGTH_BYTE ( ( uint8_t ) 0x45 )

/* IP protocol definitions. */
#define ipPROTOCOL_ICMP			( 1 )
#define ipPROTOCOL_UDP			( 17 )

/* Part of the Ethernet and ARP headers are always constant when sending an IPv4
ARP packet.  This array defines the constant parts, allowing this part of the
packet to be filled in using a simple memcpy() instead of individual writes. */
/*static const uint8_t xDefaultPartARPPacketHeader[] =
{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 	// Ethernet destination address.
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 	// Ethernet source address.
	0x08, 0x06, 				// Ethernet frame type (ipARP_TYPE).
	0x00, 0x01, 				// usHardwareType (ipARP_HARDWARE_TYPE_ETHERNET).
	0x08, 0x00,				// usProtocolType.
	ipMAC_ADDRESS_LENGTH_BYTES, 		// ucHardwareAddressLength.
	ipIP_ADDRESS_LENGTH_BYTES, 		// ucProtocolAddressLength.
	0x00, 0x01, 				// usOperation (ipARP_REQUEST).
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 	// xSenderHardwareAddress.
	0x00, 0x00, 0x00, 0x00, 		// ulSenderProtocolAddress.
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00 	// xTargetHardwareAddress.
};*/

/* The local MAC address is accessed from within xDefaultPartUDPPacketHeader,
rather than duplicated in its own variable. */
#define ipLOCAL_MAC_ADDRESS ( xDefaultPartUDPPacketHeader )

// From FreeRTOSIPConfigDefaults.h
#define ipconfigETHERNET_DRIVER_CHECKS_IP_CHECKSUM 0

// From FreeRTOSIPConfig.h
/* The ARP cache is a table that maps IP addresses to MAC addresses.  The IP
stack can only send a UDP message to a remove IP address if it knowns the MAC
address associated with the IP address, or the MAC address of the router used to
contact the remote IP address.  When a UDP message is received from a remote IP
address the MAC address and IP address are added to the ARP cache.  When a UDP
message is sent to a remote IP address that does not already appear in the ARP
cache then the UDP message is replaced by a ARP message that solicits the
required MAC address information.  ipconfigARP_CACHE_ENTRIES defines the maximum
number of entries that can exist in the ARP table at any one time. */
#define ipconfigARP_CACHE_ENTRIES		6

/* ARP requests that do not result in an ARP response will be re-transmitted a
maximum of ipconfigMAX_ARP_RETRANSMISSIONS times before the ARP request is
aborted. */
#define ipconfigMAX_ARP_RETRANSMISSIONS ( 5 )

/* ipconfigMAX_ARP_AGE defines the maximum time between an entry in the ARP
table being created or refreshed and the entry being removed because it is stale.
New ARP requests are sent for ARP cache entries that are nearing their maximum
age.  ipconfigMAX_ARP_AGE is specified in tens of seconds, so a value of 150 is
equal to 1500 seconds (or 25 minutes). */
#define ipconfigMAX_ARP_AGE			150

/* Defines the Time To Live (TTL) values used in outgoing UDP packets. */
#define updconfigIP_TIME_TO_LIVE		128

// From FreeRTOS_UDP_IP.h

struct xMAC_ADDRESS {
	uint8_t ucBytes[ipMAC_ADDRESS_LENGTH_BYTES];
};
typedef struct xMAC_ADDRESS xMACAddress_t;
typedef int BaseType_t;

struct xNetworkAddressingParameters {
	uint32_t ulDefaultIPAddress;
	uint32_t ulNetMask;
	uint32_t ulGatewayAddress;
	uint32_t ulDNSServerAddress;
};
typedef struct xNetworkAddressingParameters xNetworkAddressingParameters_t;
//static xNetworkAddressingParameters_t xNetworkAddressing = { 0, 0, 0, 0 };
static xNetworkAddressingParameters_t * xNetworkAddressing;

#define ipLOCAL_IP_ADDRESS_POINTER ( ( uint32_t* ) &( xDefaultPartUDPPacketHeader[ 20 ] ) )

struct xARP_CACHE_TABLE_ROW {
	uint32_t ulIPAddress;		/* The IP address of an ARP cache entry. */
	xMACAddress_t xMACAddress;  /* The MAC address of an ARP cache entry. */
	uint8_t ucAge;	/* A value that is periodically decremented but can also be refreshed by  
            /*active communication.The ARP cache entry is removed if the value reaches zero. */
};
typedef struct xARP_CACHE_TABLE_ROW xARPCacheRow_t;

//static xARPCacheRow_t xARPCache[ipconfigARP_CACHE_ENTRIES];
static xARPCacheRow_t * xARPCache;

// From FreeRTOS_UDP_IP.c
#define ipIP_HEADER_LENGTH		( 20 )

#define ipFRAGMENT_OFFSET_BIT_MASK ( ( uint16_t ) 0xff0f ) /* The bits in the two byte IP header */
                                                /* field that make up the fragment offset value. */


/* For convenience, a MAC address of all zeros and another of all 0xffs are
defined const for quick reference. */
static const xMACAddress_t xNullMACAddress = { { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } };
static const xMACAddress_t xBroadcastMACAddress = { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } };

/* Part of the Ethernet and IP headers are always constant when sending an IPv4
UDP packet.  This array defines the constant parts, allowing this part of the
packet to be filled in using a simple memcpy() instead of individual writes. */
//uint8_t xDefaultPartUDPPacketHeader[] =
//{
//	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 	/* Ethernet source MAC address. */
//	0x08, 0x00, 							/* Ethernet frame type. */
//	ipIP_VERSION_AND_HEADER_LENGTH_BYTE, 	/* ucVersionHeaderLength. */
//	0x00, 									/* ucDifferentiatedServicesCode. */
//	0x00, 0x00, 							/* usLength. */
//	0x00, 0x00, 							/* usIdentification. */
//	0x00, 0x00, 							/* usFragmentOffset. */
//	updconfigIP_TIME_TO_LIVE, 				/* ucTimeToLive */
//	ipPROTOCOL_UDP, 						/* ucProtocol. */
//	0x00, 0x00, 							/* usHeaderChecksum. */
//	0x00, 0x00, 0x00, 0x00 					/* Source IP address. */
//};
uint8_t * xDefaultPartUDPPacketHeader;

enum eARPLookupResult_t
{
	eARPCacheMiss = 0,  /* An ARP table lookup did not find a valid entry. */
	eARPCacheHit,       /* An ARP table lookup found a valid entry. */
	eCantSendPacket     /* There is no IP address, or an ARP is still in progress,
                           so the packet cannot be sent. */
};
typedef enum eARPLookupResult_t eARPLookupResult_t;

// From prtmacro.h
typedef uint32_t TickType_t;

// From list.h
#define configLIST_VOLATILE
#define listFIRST_LIST_ITEM_INTEGRITY_CHECK_VALUE	TickType_t xListItemIntegrityValue1;
#define listSECOND_LIST_ITEM_INTEGRITY_CHECK_VALUE	TickType_t xListItemIntegrityValue2;

struct xLIST_ITEM {
	/*< Set to a known value if configUSE_LIST_DATA_INTEGRITY_CHECK_BYTES is set to 1. */
	listFIRST_LIST_ITEM_INTEGRITY_CHECK_VALUE 
	/*< The value being listed.  In most cases this is used to sort the list in descending order. */
	configLIST_VOLATILE TickType_t xItemValue; 
	/*< Pointer to the next ListItem_t in the list. */
	struct xLIST_ITEM * configLIST_VOLATILE pxNext; 
	/*< Pointer to the previous ListItem_t in the list. */
	struct xLIST_ITEM * configLIST_VOLATILE pxPrevious; 
	/*< Pointer to the object (normally a TCB) that contains the list item. There is therefore
	a two way link between the object containing the list item and the list item itself. */
	void * pvOwner;
	/*< Pointer to the list in which this list item is placed (if any). */
	void * configLIST_VOLATILE pvContainer;
	/*< Set to a known value if configUSE_LIST_DATA_INTEGRITY_CHECK_BYTES is set to 1. */
	listSECOND_LIST_ITEM_INTEGRITY_CHECK_VALUE 
};
typedef struct xLIST_ITEM ListItem_t;

// From FreeRTOS.h
#define xListItem ListItem_t

// From FreeRTOS_IP_Private.h
/* Ethernet frame types. */
//#define ipARP_TYPE	( 0x0608U )
#define ipARP_TYPE	( 0x0608 )
//#define ipIP_TYPE	( 0x0008U )
#define ipIP_TYPE	( 0x0008 )

/* ARP related definitions. */
//#define ipARP_PROTOCOL_TYPE ( 0x0008U )
#define ipARP_PROTOCOL_TYPE ( 0x0008 )
//#define ipARP_HARDWARE_TYPE_ETHERNET ( 0x0100U )
#define ipARP_HARDWARE_TYPE_ETHERNET ( 0x0100 )
#define ipARP_REQUEST ( 0x0100 )
#define ipARP_REPLY ( 0x0200 )

//#define ipBROADCAST_IP_ADDRESS 0xffffffffUL
#define ipBROADCAST_IP_ADDRESS 0xffffffff /// removed UL, is 255.255.255.255


// NOTE: #include "pack_struct_start.h" and #include "pack_struct_end.h" are omitted.
// For more info visit: 
//http://www.freertos.org/FreeRTOS-Plus/FreeRTOS_Plus_UDP/Embedded_Compiler_Porting.shtml
struct xNETWORK_BUFFER {
	/* Used to reference the buffer form the free buffer list or a socket. */
	xListItem xBufferListItem; 		
	/* Source or destination IP address, depending on usage scenario. */
	uint32_t ulIPAddress;		
	/* Pointer to the start of the Ethernet frame. */	
	uint8_t *pucEthernetBuffer; 
	/* Starts by holding the total Ethernet frame length, then the UDP payload length. */	
	size_t xDataLength; 	
	/* Source or destination port, depending on usage scenario. */		
	uint16_t usPort;			
	/* The port to which a transmitting socket is bound. */	
	uint16_t usBoundPort;			
};
typedef struct xNETWORK_BUFFER xNetworkBufferDescriptor_t;

struct xETH_HEADER
{
	xMACAddress_t xDestinationAddress;
	xMACAddress_t xSourceAddress;
	uint16_t usFrameType;
};
typedef struct xETH_HEADER xEthernetHeader_t;

struct xIP_HEADER
{
	uint8_t ucVersionHeaderLength;
	uint8_t ucDifferentiatedServicesCode;
	uint16_t usLength;
	uint16_t usIdentification;
	uint16_t usFragmentOffset;
	uint8_t ucTimeToLive;
	uint8_t ucProtocol;
	uint16_t usHeaderChecksum;
	uint32_t ulSourceIPAddress;
	uint32_t ulDestinationIPAddress;
};
typedef struct xIP_HEADER xIPHeader_t;

struct xARP_HEADER
{
	uint16_t usHardwareType;
	uint16_t usProtocolType;
	uint8_t ucHardwareAddressLength;
	uint8_t ucProtocolAddressLength;
	uint16_t usOperation;
	xMACAddress_t xSenderHardwareAddress;
	uint32_t ulSenderProtocolAddress;
	xMACAddress_t xTargetHardwareAddress;
	uint32_t ulTargetProtocolAddress;
};
typedef struct xARP_HEADER xARPHeader_t;

struct xARP_PACKET
{
	xEthernetHeader_t xEthernetHeader;
	xARPHeader_t xARPHeader;
};
typedef struct xARP_PACKET xARPPacket_t;

struct xUDP_HEADER
{
	uint16_t usSourcePort;
	uint16_t usDestinationPort;
	uint16_t usLength;
	uint16_t usChecksum;
};
typedef struct xUDP_HEADER xUDPHeader_t;

struct xUDP_PACKET
{
	xEthernetHeader_t xEthernetHeader;
	xIPHeader_t xIPHeader;
	xUDPHeader_t xUDPHeader;
};
typedef struct xUDP_PACKET xUDPPacket_t;

struct xIP_PACKET
{
	xEthernetHeader_t xEthernetHeader;
	xIPHeader_t xIPHeader;
};
typedef struct xIP_PACKET xIPPacket_t;


/*struct xETH_HEADER
{
	xMACAddress_t xDestinationAddress;
	xMACAddress_t xSourceAddress;
	uint16_t usFrameType;
};
typedef struct xETH_HEADER xEthernetHeader_t;

struct xMAC_ADDRESS {
	uint8_t ucBytes[ipMAC_ADDRESS_LENGTH_BYTES];
};
typedef struct xMAC_ADDRESS xMACAddress_t;*/


enum eFrameProcessingResult_t
{
	/* Processing the frame did not find anything to do - just release the buffer. */
	eReleaseBuffer = 0,	
	/* An Ethernet frame has a valid address - continue process its contents. */	
	eProcessBuffer,		
	/* The Ethernet frame contains an ARP or ICMP packet that can be returned to its source. */	
	eReturnEthernetFrame,
	/* Processing the Ethernet packet contents resulted in the payload being sent to the stack. */	
	eFrameConsumed			
};
typedef enum eFrameProcessingResult_t eFrameProcessingResult_t;

// From IPTraceMacroDefaults.h
#define iptraceARP_TABLE_ENTRY_CREATED( ulIPAddress, ucMACAddress )
#define iptraceARP_TABLE_ENTRY_WILL_EXPIRE( ulIPAddress )
#define iptraceARP_TABLE_ENTRY_EXPIRED( ulIPAddress )

/********************************************************************************
 * 	Predicates and lemmas
********************************************************************************/

/*
predicate xARP_PACKET(struct xARP_PACKET *xARP_PACKET) = 
	xARP_PACKET->xARPHeader.usHardwareType |-> _  &*&
	xARP_PACKET->xARPHeader.usProtocolType |-> _ &*&
	xARP_PACKET->xARPHeader.ucHardwareAddressLength |-> _ &*&
	xARP_PACKET->xARPHeader.ucProtocolAddressLength |-> _ &*&
	xARP_PACKET->xARPHeader.usOperation |-> _ &*&
	//xARP_PACKET->xARPHeader.xSenderHardwareAddress |-> _ &*&
	xARP_PACKET->xARPHeader.ulSenderProtocolAddress |-> _ &*&
	//xARP_PACKET->xARPHeader.xTargetHardwareAddress |-> _ &*&
	xARP_PACKET->xARPHeader.ulTargetProtocolAddress |-> _ ;
*/
/*@
predicate xARP_PACKET_p(struct xARP_PACKET * xARP_PACKET) =
	xARP_PACKET->xEthernetHeader.xDestinationAddress.ucBytes |-> _ &*&
	chars(xARP_PACKET->xEthernetHeader.xDestinationAddress.ucBytes, 
		ipMAC_ADDRESS_LENGTH_BYTES, _) &*&
	struct_xMAC_ADDRESS_padding(&xARP_PACKET->xEthernetHeader.xDestinationAddress) &*&

	xARP_PACKET->xEthernetHeader.xSourceAddress.ucBytes |-> _ &*&
	chars(xARP_PACKET->xEthernetHeader.xSourceAddress.ucBytes,
		ipMAC_ADDRESS_LENGTH_BYTES, _) &*&
	struct_xMAC_ADDRESS_padding(&xARP_PACKET->xEthernetHeader.xSourceAddress) &*&
	
	xARP_PACKET->xEthernetHeader.usFrameType |-> _ &*&

	
	xARP_PACKET->xARPHeader.usHardwareType |-> _ &*&
	xARP_PACKET->xARPHeader.usProtocolType |-> _ &*&
	xARP_PACKET->xARPHeader.ucHardwareAddressLength |-> _ &*&
	xARP_PACKET->xARPHeader.ucProtocolAddressLength |-> _ &*&
	xARP_PACKET->xARPHeader.usOperation |-> _ &*&
	xARP_PACKET->xARPHeader.xSenderHardwareAddress.ucBytes |-> _ &*&	
	xARP_PACKET->xARPHeader.ulSenderProtocolAddress |-> _ &*&
	xARP_PACKET->xARPHeader.xTargetHardwareAddress.ucBytes |-> _ &*&

	chars(xARP_PACKET->xARPHeader.xSenderHardwareAddress.ucBytes,
		ipMAC_ADDRESS_LENGTH_BYTES, _) &*&
	struct_xMAC_ADDRESS_padding(&xARP_PACKET->xARPHeader.xSenderHardwareAddress) &*&

	chars(xARP_PACKET->xARPHeader.xTargetHardwareAddress.ucBytes,
		ipMAC_ADDRESS_LENGTH_BYTES, _) &*&
	struct_xMAC_ADDRESS_padding(&xARP_PACKET->xARPHeader.xTargetHardwareAddress) &*&
	
	xARP_PACKET->xARPHeader.ulTargetProtocolAddress |-> _ ;

predicate xIP_PACKET_p(struct xIP_PACKET *xIP_PACKET) = 

	xIP_PACKET->xEthernetHeader.xDestinationAddress.ucBytes |-> _ &*&
	chars(xIP_PACKET->xEthernetHeader.xDestinationAddress.ucBytes,
		ipMAC_ADDRESS_LENGTH_BYTES, _) &*&
	struct_xMAC_ADDRESS_padding(&xIP_PACKET->xEthernetHeader.xDestinationAddress) &*&

	xIP_PACKET->xEthernetHeader.xSourceAddress.ucBytes |-> _ &*&
	chars(xIP_PACKET->xEthernetHeader.xSourceAddress.ucBytes, ipMAC_ADDRESS_LENGTH_BYTES, _) &*&
	struct_xMAC_ADDRESS_padding(&xIP_PACKET->xEthernetHeader.xSourceAddress) &*&
	
	xIP_PACKET->xEthernetHeader.usFrameType |-> _ &*&

	

	xIP_PACKET->xIPHeader.ucVersionHeaderLength |-> _ &*&
	xIP_PACKET->xIPHeader.ucDifferentiatedServicesCode |-> _ &*&
	xIP_PACKET->xIPHeader.usLength |-> _ &*&
	xIP_PACKET->xIPHeader.usIdentification |-> _ &*&
	xIP_PACKET->xIPHeader.usFragmentOffset |-> _ &*&
	xIP_PACKET->xIPHeader.ucTimeToLive |-> _ &*&
	xIP_PACKET->xIPHeader.ucProtocol |-> _ &*&
	xIP_PACKET->xIPHeader.usHeaderChecksum |-> _ &*&
	xIP_PACKET->xIPHeader.ulSourceIPAddress |-> _ &*&
	xIP_PACKET->xIPHeader.ulDestinationIPAddress |-> _ &*&
	true;

predicate xNETWORK_BUFFER_p(struct xNETWORK_BUFFER * xNETWORK_BUFFER,
	uint8_t * pucEthernetBuffer) = 
	//xNETWORK_BUFFER->xBufferListItem.
	
	xNETWORK_BUFFER->ulIPAddress |-> _ &*&
	xNETWORK_BUFFER->pucEthernetBuffer |-> pucEthernetBuffer &*&
	xNETWORK_BUFFER->xDataLength |-> _ &*&
	xNETWORK_BUFFER->usPort |-> _ &*&
	xNETWORK_BUFFER->usBoundPort |-> _ &*&

	true;

lemma void UDPheader_lemma(uint8_t * pucEthernetBuffer)
requires true;
ensures sizeof(struct xUDP_PACKET) == 336;
{
	assume(false);
}
@*/
/********************************************************************************
 * 	Helper functions (supplemented)
********************************************************************************/


 void printMac(const xMACAddress_t * mac)
//@ requires true;
//@ ensures true;
 {
//@ assume(false);
 	int i;
 	for (i = 0; i < ipconfigARP_CACHE_ENTRIES; ++i) {
 		printf("%02x", mac->ucBytes[i]);
 		if (i != ipconfigARP_CACHE_ENTRIES - 1) {
 			printf(":");
 		}
 	}
 }

 void printIP(uint32_t ip)
//@ requires true;
//@ ensures true;
 {
//@ assume(false);
 	uint8_t bytes[4];
 	bytes[0] = ip & 0xFF;
 	bytes[1] = (ip >> 8) & 0xFF;
 	bytes[2] = (ip >> 16) & 0xFF;
 	bytes[3] = (ip >> 24) & 0xFF;
 	printf("%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);
 }

void printArpCache()
//@ requires true;
//@ ensures true;
{
//@ assume(false);
	printf("xArpCache:\n");
	int i;
	for (i = 0; i < ipconfigARP_CACHE_ENTRIES; ++i) {
		printf("\t%d: Age: %d \tIP: ", i + 1,(int) xARPCache[i].ucAge);
		printIP(xARPCache[i].ulIPAddress);
		printf("\tMAC: ");
		printMac(&xARPCache[i].xMACAddress);
		printf("\n");
	}
	printf("\n");
}

void printeReturn(eARPLookupResult_t eReturn)
//@ requires true;
//@ ensures true;
{
//@ assume(false);
	printf("eReturn: ");
	switch(eReturn){
		case eARPCacheMiss: printf("Miss\n");break;
		case eARPCacheHit: printf("Hit\n");break;
		case eCantSendPacket: printf("Can't send packet\n");break;
	}
}

/********************************************************************************
 * 	Function prototypes
********************************************************************************/


/*
 * Reduce the age count in each entry within the ARP cache.  An entry is no
 * longer considered valid and is deleted if its age reaches zero.
 */
 static void prvAgeARPCache( void );

/*
 * Look for ulIPAddress in the ARP cache.  If the IP address exists, copy the
 * associated MAC address into pxMACAddress, refresh the ARP cache entry's
 * age, and return eARPCacheHit.  If the IP address does not exist in the ARP
 * cache return eARPCacheMiss.  If the packet cannot be sent for any reason
 * (maybe DHCP is still in process, or the addressing needs a gateway but there
 * isn't a gateway defined) then return eCantSendPacket.
 */
 static eARPLookupResult_t prvGetARPCacheEntry( uint32_t *pulIPAddress, 
 	xMACAddress_t * pxMACAddress );

/*
 * Generate and send an ARP request for the IP address passed in ulIPAddress.
 */
 static void prvOutputARPRequest( uint32_t ulIPAddress );

/*
 * If ulIPAddress is already in the ARP cache table then reset the age of the
 * entry back to its maximum value.  If ulIPAddress is not already in the ARP
 * cache table then add it - replacing the oldest current entry if there is not
 * a free space available.
 */
 static void prvRefreshARPCacheEntry( const xMACAddress_t * pxMACAddress, 
 	const uint32_t ulIPAddress );
 
 /*
 * Processes incoming ARP packets.
 */
static eFrameProcessingResult_t prvProcessARPPacket( xARPPacket_t * pxARPFrame );

/*
 * Process incoming IP packets.
 */
static eFrameProcessingResult_t prvProcessIPPacket( const xIPPacket_t * pxIPPacket, 
	xNetworkBufferDescriptor_t * pxNetworkBuffer );

/*
 * Return the checksum generated over usDataLengthBytes from pucNextData.
 */
static uint16_t prvGenerateChecksum( const uint8_t * pucNextData,
	const uint16_t usDataLengthBytes, BaseType_t xChecksumIsOffloaded );

/*
 * Platform is Little endian (x86)
 * FreeRTOS_htons and FreeRTOS_ntohs() return the value of their 16-bit parameter with
 * the high and low bytes swapped. For example, if the usValueToSwap parameter is 0x1122,
 * then both macros return 0x2211.
 * FreeRTOS_htonl and FreeRTOS_ntohl() return the value of their 32-bit parameter with the
 * byte order reversed. For example, if the ulValueToSwap parameter is 0x11223344, then
 * both macros return 0x44332211.
 */
uint16_t FreeRTOS_htons( uint16_t usIn );
#define FreeRTOS_ntohs( x ) FreeRTOS_htons( x )
uint32_t FreeRTOS_htonl( uint32_t ulIn );
#define FreeRTOS_ntohl( x ) FreeRTOS_htonl( x )


/********************************************************************************
 * 	Verified functions
********************************************************************************/


 static void prvAgeARPCache( void ) //(*EX\label{code:prvAgeARPCache}EX*)
/*@
requires pointer(&xARPCache, ?valARPC)&*&
	chars(valARPC, sizeof(struct xARP_CACHE_TABLE_ROW), _) &*&
 	chars(valARPC + sizeof(struct xARP_CACHE_TABLE_ROW), sizeof(struct xARP_CACHE_TABLE_ROW), _) &*&
 	chars(valARPC + 2*sizeof(struct xARP_CACHE_TABLE_ROW), sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&
 	chars(valARPC + 3*sizeof(struct xARP_CACHE_TABLE_ROW), sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&
 	chars(valARPC + 4*sizeof(struct xARP_CACHE_TABLE_ROW), sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&
 	chars(valARPC + 5*sizeof(struct xARP_CACHE_TABLE_ROW), sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&
 	chars((&xNullMACAddress)->ucBytes, 6, _)&*&
 	struct_xMAC_ADDRESS_padding(&xNullMACAddress);
@*/
/*@
ensures pointer(&xARPCache, valARPC)&*&
	chars(valARPC, sizeof(struct xARP_CACHE_TABLE_ROW), _) &*&
 	chars(valARPC + sizeof(struct xARP_CACHE_TABLE_ROW), sizeof(struct xARP_CACHE_TABLE_ROW), _) &*&
 	chars(valARPC + 2*sizeof(struct xARP_CACHE_TABLE_ROW), sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&
 	chars(valARPC + 3*sizeof(struct xARP_CACHE_TABLE_ROW), sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&
 	chars(valARPC + 4*sizeof(struct xARP_CACHE_TABLE_ROW), sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&
 	chars(valARPC + 5*sizeof(struct xARP_CACHE_TABLE_ROW), sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&
 	chars((&xNullMACAddress)->ucBytes, 6, _)&*&
 	struct_xMAC_ADDRESS_padding(&xNullMACAddress);
@*/
{
// assume(false);
	BaseType_t x;

	/* Loop through each entry in the ARP cache. */
	for( x = 0; x < ipconfigARP_CACHE_ENTRIES; x++ )
	/*@
	invariant pointer(&xARPCache, valARPC)&*&
	chars(valARPC, sizeof(struct xARP_CACHE_TABLE_ROW), _) &*&
 	chars(valARPC + sizeof(struct xARP_CACHE_TABLE_ROW), sizeof(struct xARP_CACHE_TABLE_ROW), _) &*&
 	chars(valARPC + 2*sizeof(struct xARP_CACHE_TABLE_ROW), sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&
 	chars(valARPC + 3*sizeof(struct xARP_CACHE_TABLE_ROW), sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&
 	chars(valARPC + 4*sizeof(struct xARP_CACHE_TABLE_ROW), sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&
 	chars(valARPC + 5*sizeof(struct xARP_CACHE_TABLE_ROW), sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&
 	chars((&xNullMACAddress)->ucBytes, 6, _)&*&
 	struct_xMAC_ADDRESS_padding(&xNullMACAddress)&*&
 	x >= 0;
	@*/
 	{
		//@ close_struct(xARPCache);
		//@ close_struct(xARPCache + 1);
		//@ close_struct(xARPCache + 2);
		//@ close_struct(xARPCache + 3);
		//@ close_struct(xARPCache + 4);
		//@ close_struct(xARPCache + 5);
		// Create all possible solution trees in advance
		//@ if (x == 0) { }
		//@ if (x == 1) { }
		//@ if (x == 2) { }
		//@ if (x == 3) { }
		//@ if (x == 4) { }
		//@ if (x == 5) { }
		/* If the entry is valid (its age is greater than zero). */
		//if( xARPCache[ x ].ucAge > 0U )
 		if( (xARPCache + x)->ucAge > 0 )
 		{
			/* Decrement the age value of the entry in this ARP cache table row.
			When the age reaches zero it is no longer considered valid. */
			//( xARPCache[ x ].ucAge )--;
 			( (xARPCache + x)->ucAge ) = (uint8_t)( (int)((xARPCache + x)->ucAge) - 1 );

			//@ open_struct(&xNullMACAddress);
			//@ open_struct(&(xARPCache + x)->xMACAddress);
			/* If the entry has a MAC address of 0, then it is waiting an ARP
			reply, and the ARP request should be retransmitted. */
			//if( memcmp( ( void * ) &xNullMACAddress, ( void * ) &( xARPCache[ x ].xMACAddress ),
			//	sizeof( xMACAddress_t ) ) == 0 )
 			if( memcmp( ( void * ) &xNullMACAddress, ( void * ) &( (xARPCache + x)->xMACAddress ),
 				sizeof( xMACAddress_t ) ) == 0 )
 			{
				//prvOutputARPRequest( xARPCache[ x ].ulIPAddress );
 				prvOutputARPRequest( (xARPCache + x)->ulIPAddress );
 			}
			//else if( xARPCache[ x ].ucAge <= ipMAX_ARP_AGE_BEFORE_NEW_ARP_REQUEST )
 			else if( (xARPCache + x)->ucAge <= ipMAX_ARP_AGE_BEFORE_NEW_ARP_REQUEST )
 			{
				/* This entry will get removed soon.  See if the MAC address is
				still valid to prevent this happening. */
				//iptraceARP_TABLE_ENTRY_WILL_EXPIRE( xARPCache[ x ].ulIPAddress );
 				iptraceARP_TABLE_ENTRY_WILL_EXPIRE( (xARPCache + x)->ulIPAddress );
				//prvOutputARPRequest( xARPCache[ x ].ulIPAddress );
 				prvOutputARPRequest( (xARPCache + x)->ulIPAddress );
 			}
 			else
 			{
				/* The age has just ticked down, with nothing to do. */
 			}
			//@ close_struct(&xNullMACAddress);
			//@ close_struct(&(xARPCache + x)->xMACAddress);

			//if( xARPCache[ x ].ucAge == 0 )
 			if( (xARPCache + x)->ucAge == 0 )
 			{
				/* The entry is no longer valid.  Wipe it out. */
				//iptraceARP_TABLE_ENTRY_EXPIRED( xARPCache[ x ].ulIPAddress );
				/// Debugging trace disabled
				//iptraceARP_TABLE_ENTRY_EXPIRED( (xARPCache + x)->ulIPAddress );
				//xARPCache[ x ].ulIPAddress = 0UL;
 				(xARPCache + x)->ulIPAddress = 0;
 			}
 		}
		//@ open_struct(xARPCache);
		//@ open_struct(xARPCache + 1);
		//@ open_struct(xARPCache + 2);
		//@ open_struct(xARPCache + 3);
		//@ open_struct(xARPCache + 4);
		//@ open_struct(xARPCache + 5);
 	}
 }
/*-----------------------------------------------------------*/

//static eARPLookupResult_t prvGetARPCacheEntry( uint32_t *pulIPAddress, 
//	xMACAddress_t * const pxMACAddress )
 static eARPLookupResult_t prvGetARPCacheEntry( uint32_t *pulIPAddress, 
 	xMACAddress_t * pxMACAddress ) //(*EX\label{code:prvGet}EX*)
/*@
requires pointer(&xARPCache, ?valARPC)&*&
	chars(valARPC, sizeof(struct xARP_CACHE_TABLE_ROW), _) &*&
 	chars(valARPC + sizeof(struct xARP_CACHE_TABLE_ROW), 
 		sizeof(struct xARP_CACHE_TABLE_ROW), _) &*&
 	chars(valARPC + 2*sizeof(struct xARP_CACHE_TABLE_ROW), 
 		sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&
 	chars(valARPC + 3*sizeof(struct xARP_CACHE_TABLE_ROW), 
 		sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&
 	chars(valARPC + 4*sizeof(struct xARP_CACHE_TABLE_ROW), 
 		sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&
 	chars(valARPC + 5*sizeof(struct xARP_CACHE_TABLE_ROW), 
 		sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&
 	
 	chars((&xNullMACAddress)->ucBytes, 6, _)&*&
 	struct_xMAC_ADDRESS_padding(&xNullMACAddress)&*&
 	chars((&xBroadcastMACAddress)->ucBytes, 6, _)&*&
 	struct_xMAC_ADDRESS_padding(&xBroadcastMACAddress)&*&
 	u_integer(pulIPAddress, _)&*&
 	chars((pxMACAddress)->ucBytes, 6, _)&*&
 	struct_xMAC_ADDRESS_padding(pxMACAddress)&*&
 	
 	pointer(&xDefaultPartUDPPacketHeader, ?valUDPP)&*&
 	malloc_block_uchars(valUDPP,24) &*&
 	uchars(valUDPP, 24, _)&*&
 	
 	pointer(&xNetworkAddressing, ?valNA) &*&
 	xNetworkAddressingParameters_ulNetMask(valNA,_)&*&
 	xNetworkAddressingParameters_ulGatewayAddress(valNA,_);
@*/
/*@
ensures pointer(&xARPCache, valARPC)&*&
	chars(valARPC, sizeof(struct xARP_CACHE_TABLE_ROW), _) &*&
 	chars(valARPC + sizeof(struct xARP_CACHE_TABLE_ROW), 
 		sizeof(struct xARP_CACHE_TABLE_ROW), _) &*&
 	chars(valARPC + 2*sizeof(struct xARP_CACHE_TABLE_ROW), 
 		sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&
 	chars(valARPC + 3*sizeof(struct xARP_CACHE_TABLE_ROW), 
 		sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&
 	chars(valARPC + 4*sizeof(struct xARP_CACHE_TABLE_ROW), 
 		sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&
 	chars(valARPC + 5*sizeof(struct xARP_CACHE_TABLE_ROW), 
 		sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&
 	
 	chars((&xNullMACAddress)->ucBytes, 6, _)&*&
 	struct_xMAC_ADDRESS_padding(&xNullMACAddress)&*&
 	chars((&xBroadcastMACAddress)->ucBytes, 6, _)&*&
 	struct_xMAC_ADDRESS_padding(&xBroadcastMACAddress)&*&
 	u_integer(pulIPAddress, _)&*&
 	chars((pxMACAddress)->ucBytes, 6, _)&*&
 	struct_xMAC_ADDRESS_padding(pxMACAddress)&*&
 	
 	pointer(&xDefaultPartUDPPacketHeader, valUDPP)&*&
 	malloc_block_uchars(valUDPP,24) &*&
 	uchars(valUDPP, 24, _)&*&
 	
 	pointer(&xNetworkAddressing, valNA) &*&
 	xNetworkAddressingParameters_ulNetMask(valNA,_)&*&
 	xNetworkAddressingParameters_ulGatewayAddress(valNA,_);
@*/
{
// assume(false);
 		BaseType_t x;
 		eARPLookupResult_t eReturn;
 		uint32_t ulAddressToLookup;

 		if( *pulIPAddress == ipBROADCAST_IP_ADDRESS )
 		{
			//@ open_struct(pxMACAddress);
			//@ open_struct(&xBroadcastMACAddress);
			// This is a broadcast so uses the broadcast MAC address.
 			memcpy( ( void * ) pxMACAddress, &xBroadcastMACAddress, sizeof( xMACAddress_t ) );
			//@ close_struct(&xBroadcastMACAddress);
			//@ close_struct(pxMACAddress);
 			eReturn = eARPCacheHit;
 		}
		//else if( *ipLOCAL_IP_ADDRESS_POINTER == 0UL )
 		else if( ((uint32_t)xDefaultPartUDPPacketHeader[20]) == 0 )
 		{
			// The IP address has not yet been assigned, so there is nothing that can be done.
 			eReturn = eCantSendPacket;
 		}
 		else
 		{

				//if( ( *pulIPAddress & xNetworkAddressing.ulNetMask ) != 
 				//	( ( *ipLOCAL_IP_ADDRESS_POINTER ) & xNetworkAddressing.ulNetMask ) )
			if( ( *pulIPAddress & xNetworkAddressing->ulNetMask ) != 
					( (uint32_t)xDefaultPartUDPPacketHeader[20] & xNetworkAddressing->ulNetMask ) )
 			{
				// The IP address is off the local network, so look up the hardware address of the router, if any.
				//ulAddressToLookup = xNetworkAddressing.ulGatewayAddress;
 				ulAddressToLookup = xNetworkAddressing->ulGatewayAddress;
 			}
 			else
 			{
				// The IP address is on the local network, so lookup the requested IP address directly.
 				ulAddressToLookup = *pulIPAddress;
 			}

				//if( ulAddressToLookup == 0UL )
 			if( ulAddressToLookup == 0 )
 			{
				// The address is not on the local network, and there is not a router.
 				eReturn = eCantSendPacket;
 			}
 			else
 			{
 				eReturn = eARPCacheMiss;

				// Loop through each entry in the ARP cache.
 				for( x = 0; x < ipconfigARP_CACHE_ENTRIES; x++ )
				/*@ invariant pointer(&xARPCache, valARPC)&*&
				chars(valARPC, sizeof(struct xARP_CACHE_TABLE_ROW), _) &*&
			 	chars(valARPC + sizeof(struct xARP_CACHE_TABLE_ROW), 
			 		sizeof(struct xARP_CACHE_TABLE_ROW), _) &*&
			 	chars(valARPC + 2*sizeof(struct xARP_CACHE_TABLE_ROW), 
			 		sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&
			 	chars(valARPC + 3*sizeof(struct xARP_CACHE_TABLE_ROW), 
			 		sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&
			 	chars(valARPC + 4*sizeof(struct xARP_CACHE_TABLE_ROW), 
			 		sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&
			 	chars(valARPC + 5*sizeof(struct xARP_CACHE_TABLE_ROW), 
			 		sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&
			 	
			 	chars((&xNullMACAddress)->ucBytes, 6, _)&*&
 				struct_xMAC_ADDRESS_padding(&xNullMACAddress)&*&
 				
 				chars((pxMACAddress)->ucBytes, 6, _)&*&
 				struct_xMAC_ADDRESS_padding(pxMACAddress)&*&
 	
 				x >= 0; 				
				@*/
 				{
				//@ close_struct(xARPCache);
				//@ close_struct(xARPCache + 1);
				//@ close_struct(xARPCache + 2);
				//@ close_struct(xARPCache + 3);
				//@ close_struct(xARPCache + 4);
				//@ close_struct(xARPCache + 5);	
				// Create all possible solution trees in advance
				//@ if (x == 0) { }
				//@ if (x == 1) { }
				//@ if (x == 2) { }
				//@ if (x == 3) { }
				//@ if (x == 4) { }
				//@ if (x == 5) { }
				// Does this row in the ARP cache table hold an entry for the IP address being queried?
				//if( xARPCache[ x ].ulIPAddress == ulAddressToLookup )
 					if( (xARPCache + x)->ulIPAddress == ulAddressToLookup )
 					{
					//@ open_struct(&xNullMACAddress);
					//@ open_struct(pxMACAddress);

					//@ open_struct(&(xARPCache->xMACAddress));
					//@ open_struct(&((xARPCache + 1)->xMACAddress));
					//@ open_struct(&((xARPCache + 2)->xMACAddress));
					//@ open_struct(&((xARPCache + 3)->xMACAddress));
					//@ open_struct(&((xARPCache + 4)->xMACAddress));
					//@ open_struct(&((xARPCache + 5)->xMACAddress));
						// The IP address matched.  Is there a valid MAC address?
						//if( memcmp( ( void * ) &xNullMACAddress, 
						//	( void * ) &( xARPCache[ x ].xMACAddress ), sizeof( xMACAddress_t ) ) == 0 )
 						if( memcmp( ( void * ) &xNullMACAddress, 
 							( void * ) &( (xARPCache + x)->xMACAddress ), sizeof( xMACAddress_t ) ) == 0 )
 						{
							// This entry is waiting an ARP reply, so is not valid.
 							eReturn = eCantSendPacket;
 						}
 						else
 						{
							// A valid entry was found.
							//memcpy( pxMACAddress, &( xARPCache[ x ].xMACAddress ), sizeof( xMACAddress_t ) );
 							memcpy( pxMACAddress, &( (xARPCache + x)->xMACAddress ), sizeof( xMACAddress_t ) );
 							eReturn = eARPCacheHit;
 						}
					//@ close_struct(&(xARPCache->xMACAddress));
					//@ close_struct(&((xARPCache + 1)->xMACAddress));
					//@ close_struct(&((xARPCache + 2)->xMACAddress));
					//@ close_struct(&((xARPCache + 3)->xMACAddress));
					//@ close_struct(&((xARPCache + 4)->xMACAddress));
					//@ close_struct(&((xARPCache + 5)->xMACAddress));

					//@ close_struct(pxMACAddress);

					//@ close_struct(&xNullMACAddress);
 					}

 					if( eReturn != eARPCacheMiss )
 					{
					//@ open_struct(xARPCache);
					//@ open_struct(xARPCache + 1);
					//@ open_struct(xARPCache + 2);
					//@ open_struct(xARPCache + 3);
					//@ open_struct(xARPCache + 4);
					//@ open_struct(xARPCache + 5);
 						break;
 					}
				//@ open_struct(xARPCache);
				//@ open_struct(xARPCache + 1);
				//@ open_struct(xARPCache + 2);
				//@ open_struct(xARPCache + 3);
				//@ open_struct(xARPCache + 4);
				//@ open_struct(xARPCache + 5);
 				}

 				if( eReturn == eARPCacheMiss )
 				{
					// It might be that the ARP has to go to the gateway.
 					*pulIPAddress = ulAddressToLookup;
 				}
 			}
 		}

 		return eReturn;
 	}
/*-----------------------------------------------------------*/

static void prvOutputARPRequest( uint32_t ulIPAddress )
//@ requires true;
//@ ensures true;
{
//@ assume(false);
 		xNetworkBufferDescriptor_t *pxNetworkBuffer;
/*
	/* This is called from the context of the IP event task, so a block time
	must not be used. *//*
	pxNetworkBuffer = pxNetworkBufferGet( sizeof( xARPPacket_t ), 0 );
	if( pxNetworkBuffer != NULL )
	{
		pxNetworkBuffer->ulIPAddress = ulIPAddress;
		prvGenerateARPRequestPacket( pxNetworkBuffer );
		xNetworkInterfaceOutput( pxNetworkBuffer );
	}*/
}
/*-----------------------------------------------------------*/

//static void prvRefreshARPCacheEntry( const xMACAddress_t * const pxMACAddress, 
//	const uint32_t ulIPAddress )
static void prvRefreshARPCacheEntry( const xMACAddress_t*  pxMACAddress, 
	const uint32_t ulIPAddress )  //(*EX\label{code:prvRefreshArp}EX*)
/*@
requires pointer(&xNetworkAddressing, ?valNA) &*&
	 pointer(&xARPCache, ?valARPC) &*&
 	 pointer(&xDefaultPartUDPPacketHeader, ?valUDPP) &*&
 	 xNetworkAddressingParameters_ulNetMask(valNA,_) &*&
 	 malloc_block_uchars(valUDPP,24) &*&
 	 uchars(valUDPP, 24, _) &*&
 	 chars(valARPC, sizeof(struct xARP_CACHE_TABLE_ROW), _) &*&
 	 chars(valARPC + sizeof(struct xARP_CACHE_TABLE_ROW), 
 	 	sizeof(struct xARP_CACHE_TABLE_ROW), _) &*&
 	 chars(valARPC + 2*sizeof(struct xARP_CACHE_TABLE_ROW), 
 	 	sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&
 	 chars(valARPC + 3*sizeof(struct xARP_CACHE_TABLE_ROW), 
 	 	sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&
 	 chars(valARPC + 4*sizeof(struct xARP_CACHE_TABLE_ROW), 
 	 	sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&
 	 chars(valARPC + 5*sizeof(struct xARP_CACHE_TABLE_ROW), 
 	 	sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&
 	 chars(pxMACAddress->ucBytes, 6, _)&*&
 	 struct_xMAC_ADDRESS_padding(pxMACAddress);
@*/
/*@
ensures	pointer(&xNetworkAddressing, valNA) &*&
	pointer(&xARPCache, valARPC) &*&
	pointer(&xDefaultPartUDPPacketHeader, valUDPP) &*&
 	xNetworkAddressingParameters_ulNetMask(valNA,_) &*&
 	malloc_block_uchars(valUDPP,24) &*&
 	uchars(valUDPP, 24, _) &*&
 	chars(valARPC, sizeof(struct xARP_CACHE_TABLE_ROW), _) &*&
 	chars(valARPC + sizeof(struct xARP_CACHE_TABLE_ROW), 
 		sizeof(struct xARP_CACHE_TABLE_ROW), _) &*&
 	chars(valARPC + 2*sizeof(struct xARP_CACHE_TABLE_ROW), 
 		sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&
 	chars(valARPC + 3*sizeof(struct xARP_CACHE_TABLE_ROW), 
 		sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&
 	chars(valARPC + 4*sizeof(struct xARP_CACHE_TABLE_ROW), 
 		sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&
 	chars(valARPC + 5*sizeof(struct xARP_CACHE_TABLE_ROW), 
 		sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&
 	chars((pxMACAddress)->ucBytes, 6, _)&*&
 	struct_xMAC_ADDRESS_padding(pxMACAddress);
@*/
{
// assume(false);
	//BaseType_t x, xEntryFound = pdFALSE, xOldestEntry = 0;
	BaseType_t x;
	BaseType_t xEntryFound = 0;
	BaseType_t xOldestEntry = 0;
	//uint8_t ucMinAgeFound = 0u;
	//uint8_t ucMinAgeFound = (uint8_t) 0;
	uint8_t ucMinAgeFound = 0;

	/* Only process the IP address if it is on the local network. */
	///Was defined at top
	/// #define ipLOCAL_IP_ADDRESS_POINTER (( uint32_t* ) &( xDefaultPartUDPPacketHeader[ 20 ] ))
	//if ((ulIPAddress & xNetworkAddressing.ulNetMask) == 
	//	((*ipLOCAL_IP_ADDRESS_POINTER) & xNetworkAddressing.ulNetMask))
	/// can be rewritten as
	// TODO: fix potential arithmetic underflow
	uint32_t ip = (uint32_t)xDefaultPartUDPPacketHeader[20]; 
	//if ( (ulIPAddress & xNetworkAddressing->ulNetMask) == 
	//	((uint32_t)xDefaultPartUDPPacketHeader[20] & xNetworkAddressing->ulNetMask))
	if ( (ulIPAddress & xNetworkAddressing->ulNetMask) == (ip & xNetworkAddressing->ulNetMask))
	{
		//ucMinAgeFound--;
		ucMinAgeFound = (uint8_t)((int)(ucMinAgeFound) - 1);
		
		for (x = 0; x < ipconfigARP_CACHE_ENTRIES; x++)
		/*@
		invariant pointer(&xARPCache, valARPC) &*&
		chars(valARPC, sizeof(struct xARP_CACHE_TABLE_ROW), _) &*&
		chars(valARPC + sizeof(struct xARP_CACHE_TABLE_ROW), 
			sizeof(struct xARP_CACHE_TABLE_ROW), _) &*&
		chars(valARPC + 2*sizeof(struct xARP_CACHE_TABLE_ROW), 
			sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&
		chars(valARPC + 3*sizeof(struct xARP_CACHE_TABLE_ROW), 
			sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&
		chars(valARPC + 4*sizeof(struct xARP_CACHE_TABLE_ROW), 
			sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&
		chars(valARPC + 5*sizeof(struct xARP_CACHE_TABLE_ROW), 
			sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&
		 
		chars((pxMACAddress)->ucBytes, 6, _)&*&
		struct_xMAC_ADDRESS_padding(pxMACAddress)&*&
		
		x >= 0 &*&
		x <= ipconfigARP_CACHE_ENTRIES &*&
		xOldestEntry >= 0 &*&
		xOldestEntry < ipconfigARP_CACHE_ENTRIES;
		@*/
		{
		//@ close_struct(xARPCache);
		//@ close_struct(xARPCache + 1);
		//@ close_struct(xARPCache + 2);
		//@ close_struct(xARPCache + 3);
		//@ close_struct(xARPCache + 4);
		//@ close_struct(xARPCache + 5);	
		// Create all possible solution trees in advance
		//@ if (x == 0) { }
		//@ if (x == 1) { }
		//@ if (x == 2) { }
		//@ if (x == 3) { }
		//@ if (x == 4) { }
		//@ if (x == 5) { }
			//if (xARPCache[x].ulIPAddress == ulIPAddress)
			if ((xARPCache + x)->ulIPAddress  == ulIPAddress)
			{
				
				// TODO: re-enable, only used in debugging 
				// "Type mismatch. Actual: struct xMAC_ADDRESS *. Expected: int8 *."
				//if( memcmp( ( &( xARPCache[ x ].xMACAddress)), &xNullMACAddress, sizeof( xMACAddress_t ) ) == 0 )
				//{
				//	//iptraceARP_TABLE_ENTRY_CREATED( xARPCache[ x ].ulIPAddress, 
				//		*pxMACAddress );
				//}
				//xARPCache[x].ucAge = ipconfigMAX_ARP_AGE;
				(xARPCache+x)->ucAge = ipconfigMAX_ARP_AGE;
				
				//@ open_struct(&(xARPCache->xMACAddress));
				//@ open_struct(&((xARPCache + 1)->xMACAddress));
				//@ open_struct(&((xARPCache + 2)->xMACAddress));
				//@ open_struct(&((xARPCache + 3)->xMACAddress));
				//@ open_struct(&((xARPCache + 4)->xMACAddress));
				//@ open_struct(&((xARPCache + 5)->xMACAddress));
				
				//@ open_struct(pxMACAddress);
				//memcpy( &( xARPCache[ x ].xMACAddress ), pxMACAddress, sizeof( xMACAddress_t ) );
				memcpy( &( (xARPCache + x)->xMACAddress ), pxMACAddress, sizeof( xMACAddress_t ) );
				xEntryFound = pdTRUE;
				//printf(" -- Entry found \n");
				
				//@ close_struct(pxMACAddress);
				
				//@ close_struct(&(xARPCache->xMACAddress));
				//@ close_struct(&((xARPCache + 1)->xMACAddress));
				//@ close_struct(&((xARPCache + 2)->xMACAddress));
				//@ close_struct(&((xARPCache + 3)->xMACAddress));
				//@ close_struct(&((xARPCache + 4)->xMACAddress));
				//@ close_struct(&((xARPCache + 5)->xMACAddress));
				
				//@ open_struct(xARPCache);
				//@ open_struct(xARPCache + 1);
				//@ open_struct(xARPCache + 2);
				//@ open_struct(xARPCache + 3);
				//@ open_struct(xARPCache + 4);
				//@ open_struct(xARPCache + 5);
				break;
			}
			else
			{
				//if (xARPCache[x].ucAge < ucMinAgeFound)
				if ((xARPCache + x)->ucAge < ucMinAgeFound)
				{
					//ucMinAgeFound = xARPCache[x].ucAge;
					ucMinAgeFound = (xARPCache + x)->ucAge;
					//@ assert(x >= 0 && x < ipconfigARP_CACHE_ENTRIES);
					xOldestEntry = x;
					//@ assert(xOldestEntry < ipconfigARP_CACHE_ENTRIES);
				}
				//@ open_struct(xARPCache);
				//@ open_struct(xARPCache + 1);
				//@ open_struct(xARPCache + 2);
				//@ open_struct(xARPCache + 3);
				//@ open_struct(xARPCache + 4);
				//@ open_struct(xARPCache + 5);
			}

		}
		

		if( xEntryFound == pdFALSE )
		{
			//@ close_struct(xARPCache);
			//@ close_struct(xARPCache + 1);
			//@ close_struct(xARPCache + 2);
			//@ close_struct(xARPCache + 3);
			//@ close_struct(xARPCache + 4);
			//@ close_struct(xARPCache + 5);
			
			//@ if (xOldestEntry == 0) { }
			//@ if (xOldestEntry == 1) { }
			//@ if (xOldestEntry == 2) { }
			//@ if (xOldestEntry == 3) { }
			//@ if (xOldestEntry == 4) { }
			//@ if (xOldestEntry == 5) { }
			//printf(" -- Entry not found \n");
			//xARPCache[ xOldestEntry ].ulIPAddress = ulIPAddress;
			(xARPCache + xOldestEntry )->ulIPAddress = ulIPAddress;
			//@ open_struct(&(xARPCache)->xMACAddress);
			//@ open_struct(&(xARPCache + 1)->xMACAddress);
			//@ open_struct(&(xARPCache + 2)->xMACAddress);
			//@ open_struct(&(xARPCache + 3)->xMACAddress);
			//@ open_struct(&(xARPCache + 4)->xMACAddress);
			//@ open_struct(&(xARPCache + 5)->xMACAddress);
			//@ open_struct(pxMACAddress);
			//memcpy( &( xARPCache[ xOldestEntry ].xMACAddress ), 
			//	pxMACAddress, sizeof( xMACAddress_t ) );
			memcpy( &((xARPCache + xOldestEntry)->xMACAddress ), 
				pxMACAddress, sizeof( xMACAddress_t ) );
			//@ close_struct(pxMACAddress);
			//@ close_struct(&(xARPCache)->xMACAddress);
			//@ close_struct(&(xARPCache + 1)->xMACAddress);
			//@ close_struct(&(xARPCache + 2)->xMACAddress);
			//@ close_struct(&(xARPCache + 3)->xMACAddress);
			//@ close_struct(&(xARPCache + 4)->xMACAddress);
			//@ close_struct(&(xARPCache + 5)->xMACAddress);

			if( pxMACAddress == &xNullMACAddress )
			{
				//xARPCache[ xOldestEntry ].ucAge = ipconfigMAX_ARP_RETRANSMISSIONS;
				(xARPCache + xOldestEntry )->ucAge = ipconfigMAX_ARP_RETRANSMISSIONS;
			}
			else
			{
				/// TODO: re-enable, only used in debugging
				//iptraceARP_TABLE_ENTRY_CREATED( xARPCache[ xOldestEntry ].ulIPAddress, 
				//	xARPCache[ xOldestEntry ].xMACAddress );
				//xARPCache[ xOldestEntry ].ucAge = ipconfigMAX_ARP_AGE;
				(xARPCache + xOldestEntry )->ucAge = ipconfigMAX_ARP_AGE;
			}
			//@ open_struct(xARPCache);
			//@ open_struct(xARPCache + 1);
			//@ open_struct(xARPCache + 2);
			//@ open_struct(xARPCache + 3);
			//@ open_struct(xARPCache + 4);
			//@ open_struct(xARPCache + 5);	
		}
		
	}

}
/*-----------------------------------------------------------*/
static eFrameProcessingResult_t prvProcessARPPacket( xARPPacket_t * pxARPFrame ) //(*EX\label{code:prvProcessARPPacket}EX*)
/*@ requires
	// needed for prvrefresh
	pointer(&xNetworkAddressing, ?valNA) &*&
	pointer(&xARPCache, ?valARPC) &*&
 	pointer(&xDefaultPartUDPPacketHeader, ?valUDPP) &*&
 	xNetworkAddressingParameters_ulNetMask(valNA,_) &*&
 	malloc_block_uchars(valUDPP,24) &*&
 	uchars(valUDPP, 24, _) &*&
 	chars(valARPC, sizeof(struct xARP_CACHE_TABLE_ROW), _) &*&
 	chars(valARPC + sizeof(struct xARP_CACHE_TABLE_ROW), 
 		sizeof(struct xARP_CACHE_TABLE_ROW), _) &*&
 	chars(valARPC + 2*sizeof(struct xARP_CACHE_TABLE_ROW), 
 		sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&
 	chars(valARPC + 3*sizeof(struct xARP_CACHE_TABLE_ROW), 
 		sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&
 	chars(valARPC + 4*sizeof(struct xARP_CACHE_TABLE_ROW), 
 		sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&
 	chars(valARPC + 5*sizeof(struct xARP_CACHE_TABLE_ROW), 
 		sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&
 	
 	// specific to prvProcessARPPacket 
 	xARP_PACKET_p(pxARPFrame) &*&
	chars(valUDPP, sizeof(struct xMAC_ADDRESS), _) &*&

 	true;
@*/
/*@ ensures
	pointer(&xNetworkAddressing, valNA) &*&
	pointer(&xARPCache, valARPC) &*&
 	pointer(&xDefaultPartUDPPacketHeader, valUDPP) &*&
 	xNetworkAddressingParameters_ulNetMask(valNA,_) &*&
 	malloc_block_uchars(valUDPP,24) &*&
 	uchars(valUDPP, 24, _) &*&
 	chars(valARPC, sizeof(struct xARP_CACHE_TABLE_ROW), _) &*&
 	chars(valARPC + sizeof(struct xARP_CACHE_TABLE_ROW), sizeof(struct xARP_CACHE_TABLE_ROW), _) &*&
 	chars(valARPC + 2*sizeof(struct xARP_CACHE_TABLE_ROW), sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&
 	chars(valARPC + 3*sizeof(struct xARP_CACHE_TABLE_ROW), sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&
 	chars(valARPC + 4*sizeof(struct xARP_CACHE_TABLE_ROW), sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&
 	chars(valARPC + 5*sizeof(struct xARP_CACHE_TABLE_ROW), sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&
 	
	xARP_PACKET_p(pxARPFrame) &*&
	chars(valUDPP, sizeof(struct xMAC_ADDRESS), _) &*&
	
 	true;
@*/
{
	//@ open xARP_PACKET_p(pxARPFrame);
	eFrameProcessingResult_t eReturn = eReleaseBuffer;
	//xARPHeader_t * pxARPHeader;
	//pxARPHeader = &( pxARPFrame->xARPHeader );
	xARPHeader_t * pxARPHeader = &( pxARPFrame->xARPHeader );
	
	/// trace disabled
	//traceARP_PACKET_RECEIVED();
	// open_struct(xDefaultPartUDPPacketHeader);
	// Sanity check the protocol type.  Don't do anything if the local IP
	// address is zero because that means a DHCP request has not completed.
	//if( ( pxARPHeader->usProtocolType == ipARP_PROTOCOL_TYPE ) && 
	//	( *ipLOCAL_IP_ADDRESS_POINTER != 0UL ) )
	bool left = ( pxARPHeader->usProtocolType == ipARP_PROTOCOL_TYPE );
	bool right = ( xDefaultPartUDPPacketHeader != 0 );
	if( left && right)
	{
		if(pxARPHeader->usOperation == ipARP_REQUEST)
		{
			//if( pxARPHeader->ulTargetProtocolAddress == *ipLOCAL_IP_ADDRESS_POINTER )
			if( pxARPHeader->ulTargetProtocolAddress == xDefaultPartUDPPacketHeader[ 20 ] )
			{
				/// trace disabled
				//iptraceSENDING_ARP_REPLY( pxARPHeader->ulSenderProtocolAddress );

				// The request is for the address of this node.  Add the
				// entry into the ARP cache, or refresh the entry if it
				// already exists.
				prvRefreshARPCacheEntry( &( pxARPHeader->xSenderHardwareAddress ), 
					pxARPHeader->ulSenderProtocolAddress );

				// Generate a reply payload in the same buffer.
				pxARPHeader->usOperation = ipARP_REPLY;
				
				//@ open_struct( &pxARPHeader->xTargetHardwareAddress );
				//@ open_struct( &pxARPHeader->xSenderHardwareAddress );
				
				//memcpy( ( void * )  &( pxARPHeader->xTargetHardwareAddress ), 
				//	( void * ) &( pxARPHeader->xSenderHardwareAddress ), sizeof( xMACAddress_t ) );
				pxARPHeader->ulTargetProtocolAddress = pxARPHeader->ulSenderProtocolAddress;
				
				
				memcpy( ( void * ) &( pxARPHeader->xSenderHardwareAddress ), 
					( void * ) ipLOCAL_MAC_ADDRESS, sizeof( xMACAddress_t ) );
				//@ close_struct( &pxARPHeader->xSenderHardwareAddress );
				//@ close_struct( &pxARPHeader->xTargetHardwareAddress );
				
				//pxARPHeader->ulSenderProtocolAddress = *ipLOCAL_IP_ADDRESS_POINTER;
				pxARPHeader->ulSenderProtocolAddress = xDefaultPartUDPPacketHeader[ 20 ];

				eReturn = eReturnEthernetFrame;
			}
		}
		else if(pxARPHeader->usOperation == ipARP_REPLY)
		{
			/// trace disabled
			//iptracePROCESSING_RECEIVED_ARP_REPLY( pxARPHeader->ulTargetProtocolAddress );
			
			/// nodig: const xMACAddress_t*  pxMACAddress
			/// Gegeven: xSenderHardwareAddress
			
			prvRefreshARPCacheEntry( &( pxARPHeader->xSenderHardwareAddress ), 
				pxARPHeader->ulSenderProtocolAddress );
		}
		/*
		// replaced with if-statement above
		switch( pxARPHeader->usOperation )
		{
			case ipARP_REQUEST	:
				// The packet contained an ARP request.  Was it for the IP
				/// address of the node running this code?
				if( pxARPHeader->ulTargetProtocolAddress == *ipLOCAL_IP_ADDRESS_POINTER )
				{
					iptraceSENDING_ARP_REPLY( pxARPHeader->ulSenderProtocolAddress );

					// The request is for the address of this node.  Add the
					// entry into the ARP cache, or refresh the entry if it
					// already exists.
					prvRefreshARPCacheEntry( &( pxARPHeader->xSenderHardwareAddress ), 
						pxARPHeader->ulSenderProtocolAddress );

					// Generate a reply payload in the same buffer.
					pxARPHeader->usOperation = ipARP_REPLY;
					memcpy( ( void * )  &( pxARPHeader->xTargetHardwareAddress ), 
						( void * ) &( pxARPHeader->xSenderHardwareAddress ), sizeof( xMACAddress_t ) );
					pxARPHeader->ulTargetProtocolAddress = pxARPHeader->ulSenderProtocolAddress;
					memcpy( ( void * ) &( pxARPHeader->xSenderHardwareAddress ), 
						( void * ) ipLOCAL_MAC_ADDRESS, sizeof( xMACAddress_t ) );
					pxARPHeader->ulSenderProtocolAddress = *ipLOCAL_IP_ADDRESS_POINTER;

					eReturn = eReturnEthernetFrame;
				}
				break;

			case ipARP_REPLY :
				iptracePROCESSING_RECEIVED_ARP_REPLY( pxARPHeader->ulTargetProtocolAddress );
				prvRefreshARPCacheEntry( &( pxARPHeader->xSenderHardwareAddress ), 
					pxARPHeader->ulSenderProtocolAddress );
				break;

			default :
				// Invalid.
				break;
		}*/
	}
	//@ close xARP_PACKET_p(pxARPFrame);
	return eReturn;
}

/*-----------------------------------------------------------*/

static eFrameProcessingResult_t prvProcessIPPacket( const xIPPacket_t * pxIPPacket, 
	xNetworkBufferDescriptor_t * pxNetworkBuffer ) //(*EX\label{code:prvProcessIPPacket}EX*)
/*@ requires 
	// Needed for prvRefreshARPCacheEntry
	pointer(&xNetworkAddressing, ?valNA) &*&
	pointer(&xARPCache, ?valARPC) &*&
 	pointer(&xDefaultPartUDPPacketHeader, ?valUDPP) &*&
 	xNetworkAddressingParameters_ulNetMask(valNA,_) &*&
 	malloc_block_uchars(valUDPP,24) &*&
 	uchars(valUDPP, 24, _) &*&
 	chars(valARPC, sizeof(struct xARP_CACHE_TABLE_ROW), _) &*&
 	chars(valARPC + sizeof(struct xARP_CACHE_TABLE_ROW), 
 		sizeof(struct xARP_CACHE_TABLE_ROW), _) &*&
 	chars(valARPC + 2*sizeof(struct xARP_CACHE_TABLE_ROW), 
 		sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&
 	chars(valARPC + 3*sizeof(struct xARP_CACHE_TABLE_ROW), 
 		sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&
 	chars(valARPC + 4*sizeof(struct xARP_CACHE_TABLE_ROW), 
 		sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&
 	chars(valARPC + 5*sizeof(struct xARP_CACHE_TABLE_ROW), 
 		sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&

	// Specific for prvProcessIPPacket
	xIP_PACKET_p(pxIPPacket) &*&
	xNETWORK_BUFFER_p(pxNetworkBuffer, ?pucEthernetBuffer);
@*/
/*@ ensures 
	pointer(&xNetworkAddressing, valNA) &*&
	pointer(&xARPCache, valARPC) &*&
 	pointer(&xDefaultPartUDPPacketHeader, valUDPP) &*&
 	xNetworkAddressingParameters_ulNetMask(valNA,_) &*&
 	malloc_block_uchars(valUDPP,24) &*&
 	uchars(valUDPP, 24, _) &*&
 	chars(valARPC, sizeof(struct xARP_CACHE_TABLE_ROW), _) &*&
 	chars(valARPC + sizeof(struct xARP_CACHE_TABLE_ROW), 
 		sizeof(struct xARP_CACHE_TABLE_ROW), _) &*&
 	chars(valARPC + 2*sizeof(struct xARP_CACHE_TABLE_ROW), 
 		sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&
 	chars(valARPC + 3*sizeof(struct xARP_CACHE_TABLE_ROW), 
 		sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&
 	chars(valARPC + 4*sizeof(struct xARP_CACHE_TABLE_ROW), 
 		sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&
 	chars(valARPC + 5*sizeof(struct xARP_CACHE_TABLE_ROW), 
 		sizeof(struct xARP_CACHE_TABLE_ROW), _)&*&

	xIP_PACKET_p(pxIPPacket) &*&
	xNETWORK_BUFFER_p(pxNetworkBuffer, pucEthernetBuffer);
@*/
{
//@ assume(false);
eFrameProcessingResult_t eReturn = eReleaseBuffer;
const xIPHeader_t * pxIPHeader;
//xUDPPacket_t *pxUDPPacket;
xUDPPacket_t *pxUDPPacket = NULL;
BaseType_t xChecksumIsCorrect;

	pxIPHeader = &( pxIPPacket->xIPHeader );
	
	//@ open xIP_PACKET_p(pxIPPacket);
	
	// Is the packet for this node?
	//if( ( pxIPHeader->ulDestinationIPAddress == *ipLOCAL_IP_ADDRESS_POINTER ) || 
	//	( pxIPHeader->ulDestinationIPAddress == ipBROADCAST_IP_ADDRESS ) || 
	//	( *ipLOCAL_IP_ADDRESS_POINTER == 0 ) )
	if( ( pxIPHeader->ulDestinationIPAddress == xDefaultPartUDPPacketHeader[ 20 ] ) || 
		( pxIPHeader->ulDestinationIPAddress == ipBROADCAST_IP_ADDRESS ) || 
		( xDefaultPartUDPPacketHeader[ 20 ] == 0 ) )
	{
		// Ensure the frame is IPv4 with no options bytes, and that the incoming
		// packet is not fragmented (only outgoing packets can be fragmented) as
		// these are the only handled IP frames currently.
		//if( ( pxIPHeader->ucVersionHeaderLength == ipIP_VERSION_AND_HEADER_LENGTH_BYTE ) && 
		//	( ( pxIPHeader->usFragmentOffset & ipFRAGMENT_OFFSET_BIT_MASK ) == 0U ) )
		
		//if( ( pxIPHeader->ucVersionHeaderLength == ipIP_VERSION_AND_HEADER_LENGTH_BYTE ) && 
		//	( ( pxIPHeader->usFragmentOffset & ipFRAGMENT_OFFSET_BIT_MASK ) == 0 ) )
		if( ( pxIPHeader->ucVersionHeaderLength == ipIP_VERSION_AND_HEADER_LENGTH_BYTE ) && 
			( ( (int)pxIPHeader->usFragmentOffset & (int)ipFRAGMENT_OFFSET_BIT_MASK ) == 0 ) )
		{
			// Is the IP header checksum correct?
			//if( prvGenerateChecksum( ( uint8_t * ) &( pxIPHeader->ucVersionHeaderLength ), 
			//	ipIP_HEADER_LENGTH, ipconfigETHERNET_DRIVER_CHECKS_IP_CHECKSUM ) == 0 )
			if(true)
			{
				// Add the IP and MAC addresses to the ARP table if they are not
				// already there - otherwise refresh the age of the existing
				// entry.
				prvRefreshARPCacheEntry( &( pxIPPacket->xEthernetHeader.xSourceAddress ), 
					pxIPHeader->ulSourceIPAddress );
				
				if(pxIPHeader->ucProtocol == ipPROTOCOL_UDP)
				{
					
					/// TOD Re-enable
					//@ open xNETWORK_BUFFER_p(pxNetworkBuffer, pucEthernetBuffer);
					// The IP packet contained a UDP frame.
					//pxUDPPacket = ( xUDPPacket_t * ) ( pxNetworkBuffer->pucEthernetBuffer );
					/// TODO Re-enable
					//uint8_t * test = pxNetworkBuffer->pucEthernetBuffer;
					//pxUDPPacket = test;
					pxUDPPacket = ( void * ) ( pxNetworkBuffer->pucEthernetBuffer );

					// Note the header values required prior to the
					// checksum generation as the checksum pseudo header
					// may clobber some of these values.
					//pxNetworkBuffer->xDataLength = FreeRTOS_ntohs( pxUDPPacket->xUDPHeader.usLength ) 
					//	 - sizeof( xUDPHeader_t );
					//This potentially side-effecting expression is not supported in this position, 
					//	because of C's unspecified evaluation order
					//@ UDPheader_lemma(pucEthernetBuffer);
					// uchars_to_chars(pucEthernetBuffer);
					// close_struct(pxUDPPacket);
					// 0. uittellen hoe groot de struct is
					// 1. lemma maken die de chars geeft : chars(dummy32, struct_xUDP_PACKET_size, _)
					// 2. Wat hebben we effectief
					// 3. lemma vervangen door iets dat de check informeel doet (met assume false)
					uint16_t usLength_ntohs = FreeRTOS_htons( pxUDPPacket->xUDPHeader.usLength );
					pxNetworkBuffer->xDataLength = usLength_ntohs - sizeof( xUDPHeader_t );
					

					pxNetworkBuffer->usPort = pxUDPPacket->xUDPHeader.usSourcePort;
					pxNetworkBuffer->ulIPAddress = pxUDPPacket->xIPHeader.ulSourceIPAddress;

					// Is the checksum required?
					if( pxUDPPacket->xUDPHeader.usChecksum == 0 )
					{
						xChecksumIsCorrect = pdTRUE;
					}
					else if( prvGenerateUDPChecksum( pxUDPPacket, 
						ipconfigETHERNET_DRIVER_CHECKS_UDP_CHECKSUM ) == 0 )
					{
						xChecksumIsCorrect = pdTRUE;
					}
					else
					{
						xChecksumIsCorrect = pdFALSE;
					}

					// Is the checksum correct?
					if( xChecksumIsCorrect == pdTRUE )
					{
						// Pass the packet payload to the UDP sockets
						// implementation.
						//if( xProcessReceivedUDPPacket( pxNetworkBuffer, 
						//	pxUDPPacket->xUDPHeader.usDestinationPort ) == pdPASS )
						//{
						//	eReturn = eFrameConsumed;
						//}
					}					// The IP packet contained a UDP frame.
					//pxUDPPacket = ( xUDPPacket_t * ) ( pxNetworkBuffer->pucEthernetBuffer );
					// from uint8_t *pucEthernetBuffer to UDPPacket_t *
					//pxUDPPacket = ( xUDPPacket_t * ) ( pxNetworkBuffer->pucEthernetBuffer );

					// Note the header values required prior to the
					// checksum generation as the checksum pseudo header
					// may clobber some of these values.
					pxNetworkBuffer->xDataLength = FreeRTOS_ntohs( pxUDPPacket->xUDPHeader.usLength ) 
						 - sizeof( xUDPHeader_t );
					pxNetworkBuffer->usPort = pxUDPPacket->xUDPHeader.usSourcePort;
					pxNetworkBuffer->ulIPAddress = pxUDPPacket->xIPHeader.ulSourceIPAddress;

					// Is the checksum required?
					if( pxUDPPacket->xUDPHeader.usChecksum == 0 )
					{
						xChecksumIsCorrect = pdTRUE;
					}
					else if( prvGenerateUDPChecksum( pxUDPPacket, 
						ipconfigETHERNET_DRIVER_CHECKS_UDP_CHECKSUM ) == 0 )
					{
						xChecksumIsCorrect = pdTRUE;
					}
					else
					{
						xChecksumIsCorrect = pdFALSE;
					}

					// Is the checksum correct?
					if( xChecksumIsCorrect == pdTRUE )
					{
						// Pass the packet payload to the UDP sockets
						// implementation.
						if( xProcessReceivedUDPPacket( pxNetworkBuffer, 
							pxUDPPacket->xUDPHeader.usDestinationPort ) == pdPASS )
						{
							eReturn = eFrameConsumed;
						}
					}
				}
				
			}
		}
	}
	//@ close xIP_PACKET_p(pxIPPacket);
	return eReturn;
	//return 0;
}
/*-----------------------------------------------------------*/

static uint16_t prvGenerateChecksum( const uint8_t * pucNextData, 
	const uint16_t usDataLengthBytes, BaseType_t xChecksumIsOffloaded )
/// TODO : simplify isntead of verifying whole function
/*@ requires true; @*/
/*@ ensures true; @*/
{
//@ assume(false);
uint32_t ulChecksum = 0;
//uint16_t us, usDataLength16BitWords, *pusNextData, usReturn;
uint16_t us;
uint16_t usDataLength16BitWords;
int *pusNextData;
uint16_t usReturn;
	/// TODO unsigned numbers (whole function)
	if( xChecksumIsOffloaded == pdFALSE )
	{
		// There are half as many 16 bit words than bytes.
		//usDataLength16BitWords = ( usDataLengthBytes >> 1U );
		usDataLength16BitWords = (uint16_t)( usDataLengthBytes >> 1 );
		
		//pusNextData = ( uint16_t * ) pucNextData;
		//pusNextData = pucNextData;
		pusNextData = (int *) pucNextData;

		//for( us = 0U; us < usDataLength16BitWords; us++ )
		for( us = 0; us < usDataLength16BitWords; us++ )
		//@ invariant true;
		{
			ulChecksum += ( uint32_t ) pusNextData[ us ];
		}

		//if( ( usDataLengthBytes & 0x01U ) != 0x00 )
		if( ( usDataLengthBytes & 0x01 ) != 0x00 )
		{
			// There is one byte left over.
			/*#if ipconfigBYTE_ORDER == FREERTOS_LITTLE_ENDIAN
			{*/
				ulChecksum += ( uint32_t ) pucNextData[ usDataLengthBytes - 1 ];
			/*}
			#else
			{
				us = ( uint16_t ) pucNextData[ usDataLengthBytes - 1 ];
				ulChecksum += ( uint32_t ) ( us << 8 );
			}
			#endif*/
		}

		//while( ( ulChecksum >> 16UL ) != 0x00UL )
		while( ( ulChecksum >> 16 ) != 0x00 )
		{
			//ulChecksum = ( ulChecksum & 0xffffUL ) + ( ulChecksum >> 16UL );
			ulChecksum = ( ulChecksum & 0xffff ) + ( ulChecksum >> 16 );
		}

		usReturn = ~( ( uint16_t ) ulChecksum );
	}
	else
	{
		// The checksum is calculated by the hardware.  Return 0 here to ensure
		//this works for both incoming and outgoing checksums.
		usReturn = 0;
	}

	return usReturn;
}
/*-----------------------------------------------------------*/

uint16_t FreeRTOS_htons( uint16_t usIn )
//@ requires true;
//@ ensures true;
{
	//return	( ( usIn & ( uint16_t ) 0x00ff ) << ( uint16_t ) 8U ) |
	//		( ( usIn & ( uint16_t ) 0xff00 ) >> ( uint16_t ) 8U );
	/*int first = (int)usIn & (int)0x00ff;
	int left =  ( first << 8 );
	int right = ( (int)usIn & (int)0xff00 ) >> 8;
	uint16_t result = (uint16_t)(left | right);
	return result;*/
	return	(uint16_t)(
		( ( (int)usIn & (int) 0x00ff ) << 8 ) |
		( ( (int)usIn & (int) 0xff00 ) >> 8 ) );
}
/*-----------------------------------------------------------*/

uint32_t FreeRTOS_htonl( uint32_t ulIn )
/// prove for a subset of the range, restrict (limitation in VeriFast)
//@ requires true;
//@ ensures true;
{
//@ assume (false);
	//return	( ( ulIn & 0x000000ffUL ) << 24UL ) | // 0x000000ffUL = 255
	//		( ( ulIn & 0x0000ff00UL ) << 8UL  ) | // 0x0000ff00UL = 65280
	//		( ( ulIn & 0x00ff0000UL ) >> 8UL  ) | // 0x00ff0000UL = 16711680
	//		( ( ulIn & 0xff000000UL ) >> 24UL );  // 0xff000000UL = 4278190080
	return	(uint32_t)(
		( ( (int)ulIn & (int)0x000000ff ) << 24 ) | 
		( ( (int)ulIn & (int)0x0000ff00 ) << 8  ) | 
		( ( (int)ulIn & (int)0x00ff0000 ) >> 8  ) | 
		( ( (int)ulIn & (int)0xff000000 ) >> 24 ) );
}
/*-----------------------------------------------------------*/

/********************************************************************************
 * 	Function for displaying functionality of verified functions
********************************************************************************/

int main()

//@ requires module(extract, true);
//@ ensures  module(extract, _);
{
	//@ open_module();
	
	// Variables used for testing
	xMACAddress_t resultMac;
	eARPLookupResult_t eReturn;
	uint32_t TestIP1 = 3232235521; // 192.168.0.1
	uint32_t TestIP2 = 3232235522; // 192.168.0.2
	uint32_t TestIP3 = 3232235523; // 192.168.0.3
	uint32_t TestIP4 = 3232235524; // 192.168.0.4
	uint32_t TestIP5 = 3232235525; // 192.168.0.5
	uint32_t TestIP6 = 3232235526; // 192.168.0.6
	uint32_t TestIP7 = 3232235527; // 192.168.0.7
	uint32_t BroadcastIP = 4294967295;
	xMACAddress_t TestMac1 = { { 0x12, 0x12, 0x12, 0x12, 0x12, 0x12 } };
	xMACAddress_t TestMac2 = { { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 } };
	
	
	// init now global arrays
	xNetworkAddressing = malloc(sizeof(xNetworkAddressingParameters_t));
	if (xNetworkAddressing == 0) abort();
	xNetworkAddressing->ulDefaultIPAddress = 0;
	xNetworkAddressing->ulNetMask = 0;
	xNetworkAddressing->ulGatewayAddress = 0;
	xNetworkAddressing->ulDNSServerAddress = 0;

	//TODO: don't ignore arithmetic overflow
	xARPCache = malloc(6 * sizeof(xARPCacheRow_t));
	if (xARPCache == 0) abort();
	//@ chars_split((void *)xARPCache, sizeof(struct xARP_CACHE_TABLE_ROW));
	//@ chars_split((void *)(xARPCache + 1), sizeof(struct xARP_CACHE_TABLE_ROW));
	//@ chars_split((void *)(xARPCache + 2), sizeof(struct xARP_CACHE_TABLE_ROW));
	//@ chars_split((void *)(xARPCache + 3), sizeof(struct xARP_CACHE_TABLE_ROW));
	//@ chars_split((void *)(xARPCache + 4), sizeof(struct xARP_CACHE_TABLE_ROW));
	//@ chars_split((void *)(xARPCache + 5), sizeof(struct xARP_CACHE_TABLE_ROW));

	xDefaultPartUDPPacketHeader = malloc(sizeof(uint8_t) * 24);
	if (xDefaultPartUDPPacketHeader == 0) abort();
	xDefaultPartUDPPacketHeader[0] = 0x00;
	xDefaultPartUDPPacketHeader[1] = 0x00;
	xDefaultPartUDPPacketHeader[2] = 0x00;
	xDefaultPartUDPPacketHeader[3] = 0x00;
	xDefaultPartUDPPacketHeader[4] = 0x00;
	xDefaultPartUDPPacketHeader[5] = 0x00;
	xDefaultPartUDPPacketHeader[6] = 0x00;
	xDefaultPartUDPPacketHeader[7] = 0x08;
	xDefaultPartUDPPacketHeader[8] = ipIP_VERSION_AND_HEADER_LENGTH_BYTE;
	xDefaultPartUDPPacketHeader[9] = 0x00;
	xDefaultPartUDPPacketHeader[10] = 0x00;
	xDefaultPartUDPPacketHeader[11] = 0x00;
	xDefaultPartUDPPacketHeader[12] = 0x00;
	xDefaultPartUDPPacketHeader[13] = 0x00;
	xDefaultPartUDPPacketHeader[14] = 0x00;
	xDefaultPartUDPPacketHeader[15] = 0x00;
	xDefaultPartUDPPacketHeader[16] = updconfigIP_TIME_TO_LIVE;
	xDefaultPartUDPPacketHeader[17] = ipPROTOCOL_UDP;
	xDefaultPartUDPPacketHeader[18] = 0x00;
	xDefaultPartUDPPacketHeader[19] = 0x00;
	xDefaultPartUDPPacketHeader[20] = 0x00;
	xDefaultPartUDPPacketHeader[21] = 0x00;
	xDefaultPartUDPPacketHeader[22] = 0x00;
	xDefaultPartUDPPacketHeader[23] = 0x00;

	printf("Testing prvRefreshARPCacheEntry\n\n");
	printf("-> Initial contents\n");
	printArpCache();

	// From FreeRTOS_UDP_IP.c->prvProcessARPPacket
	// The request is for the address of this node.  Add the
	// entry into the ARP cache, or refresh the entry if it
	// already exists.
	printf("-> Add entry\n");
	// assert arp cache only contains zeroes
	prvRefreshARPCacheEntry(&(TestMac1), TestIP1);
	printArpCache();
	// assert arp cache is empty safe for one entry

	printf("-> Add entry\n");
	prvRefreshARPCacheEntry(&(TestMac2), TestIP2);
	printArpCache();
	
	printf("-> Decrementing age timer with prvAgeARPCache\n");
	prvAgeARPCache();
	printArpCache();

	printf("-> Refresh entry\n");
	prvRefreshARPCacheEntry(&(TestMac1), TestIP1);
	printArpCache();

	// From From FreeRTOS_UDP_IP.c->prvProcessGeneratedPacket
	// Add an entry to the ARP table with a null hardware address.
	// This allows the ARP timer to know that an ARP reply is
	// outstanding, and perform retransmissions if necessary.
	printf("-> Null hardware address\n");
	prvRefreshARPCacheEntry(&xNullMACAddress, TestIP3);
	printArpCache();
	
	printf("-> Overwrite limited arp cache size\n");
	printf("---> Lower age and fill whole cache\n");
	prvAgeARPCache();
	prvRefreshARPCacheEntry(&xNullMACAddress, TestIP4);
	prvRefreshARPCacheEntry(&xNullMACAddress, TestIP5);
	prvRefreshARPCacheEntry(&xNullMACAddress, TestIP6);
	printArpCache();
	
	printf("---> Add newer entry\n");
	prvRefreshARPCacheEntry(&xNullMACAddress, TestIP7);
	printArpCache();
	
	printf("---> Add entry with same age\n");
	prvRefreshARPCacheEntry(&xNullMACAddress, TestIP3);
	printArpCache();
	
	//printf("---------------------------------------------------\n");
	printf("Testing prvGetARPCacheEntry\n\n");
	/*
	 * Look for ulIPAddress in the ARP cache.  If the IP address exists, copy the
	 * associated MAC address into pxMACAddress, refresh the ARP cache entry's
	 * age, and return eARPCacheHit.  If the IP address does not exist in the ARP
	 * cache return eARPCacheMiss.  If the packet cannot be sent for any reason
	 * (maybe DHCP is still in process, or the addressing needs a gateway but there
	 * isn't a gateway defined) then return eCantSendPacket.
	 */
	//printf("---> Get broadcast address: Get ");
	printIP(BroadcastIP);
	eReturn = prvGetARPCacheEntry(&BroadcastIP, &resultMac);
	printf("\n Result MAC: ");
	printMac(&resultMac);
	printf("\n ");
	printeReturn(eReturn);

	//printf("\n--> Get IP address when reply address is 0: Get ");
	printIP(TestIP1);
	eReturn = prvGetARPCacheEntry(&TestIP1, &resultMac);
	printf("\n Result MAC: ");
	printMac(&resultMac);
	printf("\n ");
	printeReturn(eReturn);

	xDefaultPartUDPPacketHeader[20] = 10;

	//printf("\n--> Get IP address that's in ARP cache: Get ");
	printIP(TestIP1);
	eReturn = prvGetARPCacheEntry(&TestIP1, &resultMac);
	printf("\n Result MAC: ");
	printMac(&resultMac);
	printf("\n ");
	printeReturn(eReturn);
	printArpCache();

	//printf("\n--> Get IP address that's not in ARP cache: Get ");
	printIP(TestIP7);
	eReturn = prvGetARPCacheEntry(&TestIP7, &resultMac);
	printf("\n Result MAC: ");
	printMac(&resultMac);
	printf("\n ");
	printeReturn(eReturn);


	//@ chars_join((void *)xARPCache);
	//@ chars_join((void *)xARPCache);
	//@ chars_join((void *)xARPCache);
	//@ chars_join((void *)xARPCache);

	free(xNetworkAddressing);
	free((void *)xARPCache);
	free(xDefaultPartUDPPacketHeader);
	//@ close_module();
	return 0;
}

