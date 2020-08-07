/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#define _WINSOCK_DEPRECATED_NO_WARNINGS 1

#include <msquichelper.h>

#pragma pack(push)
#pragma pack(1)

typedef struct _IPV4_HEADER {
    union {
        UINT8 VersionAndHeaderLength;   // Version and header length.
        struct {
            UINT8 HeaderLength : 4;
            UINT8 Version : 4;
        };
    };
    union {
        UINT8 TypeOfServiceAndEcnField; // Type of service & ECN (RFC 3168).
        struct {
            UINT8 EcnField : 2;
            UINT8 TypeOfService : 6;
        };
    };
    UINT16 TotalLength;                 // Total length of datagram.
    UINT16 Identification;
    union {
        UINT16 FlagsAndOffset;          // Flags and fragment offset.
        struct {
            UINT16 DontUse1 : 5;        // High bits of fragment offset.
            UINT16 MoreFragments : 1;
            UINT16 DontFragment : 1;
            UINT16 Reserved : 1;
            UINT16 DontUse2 : 8;        // Low bits of fragment offset.
        };
    };
    UINT8 TimeToLive;
    UINT8 Protocol;
    UINT16 HeaderChecksum;
    IN_ADDR SourceAddress;
    IN_ADDR DestinationAddress;
} IPV4_HEADER;

typedef struct UDP_HEADER {
   UINT16 uh_sport;
   UINT16 uh_dport;
   UINT16 uh_ulen;
   UINT16 uh_sum;
} UDP_HEADER;

typedef struct ICMP_HEADER {
   uint8_t Type;
   uint8_t Code;
   uint16_t Checksum;
   uint32_t RestOfHeader;
} ICMP_HEADER;

typedef struct ICMP_ECHO_REQUEST {
   uint8_t Type; // 8
   uint8_t Code;
   uint16_t Checksum;
   uint16_t Identifier;
   uint16_t SequenceNumber;
} ICMP_ECHO_REQUEST;

typedef struct ICMP_TIME_EXCEEDED {
   uint8_t Type; // 11
   uint8_t Code;
   uint16_t Checksum;
   uint16_t Identifier;
   uint16_t SequenceNumber;
   IPV4_HEADER RequestHeader;
   ICMP_ECHO_REQUEST IcmpRequest;
} ICMP_TIME_EXCEEDED;

#pragma pack(pop)

sockaddr_in SourceAddr;
sockaddr_in DestinationAddr;
sockaddr_in RequestAddr;
uint32_t TTL = 30;
uint32_t Timeout = 3000;
uint32_t Count = 10;

uint16_t Checksum(void* input, size_t bytes)
{
    uint16_t *data = (uint16_t*)input;
	uint32_t sum = 0;
	for (size_t i = 0; i < bytes/2; ++i) {
		sum += data[i];
	}
	sum = (sum & 0xFFFF) + (sum >> 16);
	sum = htons(0xFFFF - sum);
	return htons(sum);
}

void echo_request()
{
    WSADATA WsaData;
    if (WSAStartup(MAKEWORD(2, 2), &WsaData)) {
        printf("WSAStartup failed, %u\n", WSAGetLastError());
        return;
    }

    int Enabled = TRUE;

    SOCKET RecvSocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (RecvSocket == INVALID_SOCKET) {
        printf("socket(ICMP) failed, %u\n", WSAGetLastError());
        return;
    }

    DWORD BytesReturned;
    if (WSAIoctl(RecvSocket, FIONBIO, &Enabled, sizeof(Enabled), NULL, 0, &BytesReturned, NULL, NULL) == SOCKET_ERROR) {
        printf("Set FIONBIO failed, %u\n", WSAGetLastError());
        return;
    }

    if (bind(RecvSocket, (sockaddr*)&SourceAddr, sizeof(SourceAddr)) == SOCKET_ERROR) {
        printf("bind failed, %u\n", WSAGetLastError());
        return;
    }

    SOCKET SendSocket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (SendSocket == INVALID_SOCKET) {
        printf("socket(RAW) failed, %u\n", WSAGetLastError());
        return;
    }

    if (setsockopt(SendSocket, IPPROTO_IP, IP_HDRINCL, (char*)&Enabled, sizeof(Enabled)) == SOCKET_ERROR) {
        printf("Set IP_HDRINCL failed, %u\n", WSAGetLastError());
        return;
    }

    uint8_t SendBuffer[sizeof(IPV4_HEADER) + sizeof(ICMP_ECHO_REQUEST)] = {0};

    IPV4_HEADER* SendHeader = (IPV4_HEADER*)SendBuffer;
    SendHeader->VersionAndHeaderLength = 0x45;
    SendHeader->TotalLength = htons(sizeof(IPV4_HEADER) + sizeof(ICMP_HEADER));
    SendHeader->Identification = 1;
    SendHeader->TimeToLive = TTL;
    SendHeader->Protocol = 1;
    SendHeader->SourceAddress = SourceAddr.sin_addr;
    SendHeader->DestinationAddress = RequestAddr.sin_addr;
    SendHeader->HeaderChecksum = Checksum(SendHeader, sizeof(IPV4_HEADER));

    ICMP_ECHO_REQUEST* EchoRequest = (ICMP_ECHO_REQUEST*)(SendHeader + 1);
    EchoRequest->Type = 8;
    EchoRequest->Checksum = Checksum(EchoRequest, sizeof(ICMP_ECHO_REQUEST));

    printf("Sending %u bytes:", (uint32_t)sizeof(SendBuffer));
    for (int i = 0; i < sizeof(SendBuffer); ++i) {
        if (i % 16 == 0) printf("\n");
        printf("%02hhX", SendBuffer[i]);
    }
    printf("\n");

    for (uint32_t i = 0; i < Count; ++i) {
        if (sendto(SendSocket, (char*)SendBuffer, sizeof(SendBuffer), 0, (sockaddr*)&RequestAddr, sizeof(RequestAddr)) == SOCKET_ERROR) {
            printf("sendto failed, %u\n", WSAGetLastError());
            return;
        }
        Sleep(100);
    }
    printf("ICMP Echo Request sent.\n");

    uint8_t Recv[512] = { 0 };
    uint32_t Start = GetTickCount();
    int Count;
    do {
        if ((Count = recv(RecvSocket, (char*)Recv, sizeof(Recv), 0)) == SOCKET_ERROR) {
            int Error = WSAGetLastError();
            if (Error != WSAEWOULDBLOCK) {
                printf("recvfrom failed, %u\n", WSAGetLastError());
            }
            Sleep(100);
        }
    } while (Count == SOCKET_ERROR && (GetTickCount() - Start) < Timeout);

    if (Count == SOCKET_ERROR) {
        printf("Timeout!\n");
        return;
    }

    printf("Recevied %d bytes:", Count);
    for (int i = 0; i < Count; ++i) {
        if (i % 16 == 0) printf("\n");
        printf("%02hhX", Recv[i]);
    }

    IPV4_HEADER* Header = (IPV4_HEADER*)Recv;

    char AddrStr[64] = { 0 };
    RtlIpv4AddressToStringA(&Header->SourceAddress, AddrStr);
    printf("\nReply from: %s\n", AddrStr);

    ICMP_TIME_EXCEEDED* TimeExceeded = (ICMP_TIME_EXCEEDED*)(Header+1);
    RtlIpv4AddressToStringA(&TimeExceeded->RequestHeader.SourceAddress, AddrStr);
    printf("Origin src IP: %s\n", AddrStr);
    RtlIpv4AddressToStringA(&TimeExceeded->RequestHeader.DestinationAddress, AddrStr);
    printf("Origin dst IP: %s\n", AddrStr);
}

void echo_response()
{
    WSADATA WsaData;
    if (WSAStartup(MAKEWORD(2, 2), &WsaData)) {
        printf("WSAStartup failed, %u\n", WSAGetLastError());
        return;
    }

    SOCKET Socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (Socket == INVALID_SOCKET) {
        printf("socket failed, %u\n", WSAGetLastError());
        return;
    }

    ICMP_TIME_EXCEEDED TimeExceeded = {0};
    TimeExceeded.Type = 11;
    TimeExceeded.Checksum = Checksum(&TimeExceeded, sizeof(ICMP_HEADER));
    TimeExceeded.RequestHeader.VersionAndHeaderLength = 0x45;
    TimeExceeded.RequestHeader.TotalLength = htons(sizeof(IPV4_HEADER) + sizeof(ICMP_HEADER));
    TimeExceeded.RequestHeader.Identification = 1;
    TimeExceeded.RequestHeader.TimeToLive = 1;
    TimeExceeded.RequestHeader.Protocol = 1;
    TimeExceeded.RequestHeader.SourceAddress = DestinationAddr.sin_addr;
    TimeExceeded.RequestHeader.DestinationAddress = RequestAddr.sin_addr;
    TimeExceeded.RequestHeader.HeaderChecksum = Checksum(&TimeExceeded.RequestHeader, sizeof(TimeExceeded.RequestHeader));
    TimeExceeded.IcmpRequest.Type = 8;
    TimeExceeded.IcmpRequest.Checksum = Checksum(&TimeExceeded.IcmpRequest, sizeof(TimeExceeded.IcmpRequest));

    printf("Sending %u bytes:", (uint32_t)sizeof(TimeExceeded));
    for (int i = 0; i < sizeof(TimeExceeded); ++i) {
        if (i % 16 == 0) printf("\n");
        printf("%02hhX", ((uint8_t*)&TimeExceeded)[i]);
    }
    printf("\n");

    for (uint32_t i = 0; i < Count; ++i) {
        if (sendto(Socket, (char*)&TimeExceeded, sizeof(TimeExceeded), 0, (sockaddr*)&DestinationAddr, sizeof(DestinationAddr)) == SOCKET_ERROR) {
            printf("sendto failed, %u\n", WSAGetLastError());
            return;
        }
        Sleep(100);
    }

    printf("ICMP Time Expired sent.\n");
}

int
QUIC_MAIN_EXPORT
main(int argc, char **argv)
{
    const char* Source = "192.168.1.160";
    const char* Destination = "66.235.1.136";
    const char* Request = "3.3.3.3";

    TryGetValue(argc, argv, "source", &Source);
    TryGetValue(argc, argv, "dest", &Destination);
    TryGetValue(argc, argv, "ttl", &TTL);
    TryGetValue(argc, argv, "timeout", &Timeout);
    TryGetValue(argc, argv, "count", &Count);

    SourceAddr.sin_family = AF_INET;
    SourceAddr.sin_addr.S_un.S_addr = inet_addr(Source);
    DestinationAddr.sin_family = AF_INET;
    DestinationAddr.sin_addr.S_un.S_addr = inet_addr(Destination);
    RequestAddr.sin_family = AF_INET;
    RequestAddr.sin_addr.S_un.S_addr = inet_addr(Request);

    if (GetValue(argc, argv, "req")) {
        printf("ICMP ECHO Requests from: %s to %s\n", Source, Request);
        echo_request();
    } else if (GetValue(argc, argv, "res")) {
        printf("ICMP Time Expired to: %s\n", Destination);
        echo_response();
    } else {
        printf("Must specify -req or -res\n");
    }

    return 0;
}
