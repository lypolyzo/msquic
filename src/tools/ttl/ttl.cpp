/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include <msquichelper.h>

#define SIO_UDP_NETRESET            _WSAIOW(IOC_VENDOR,15)

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

#pragma pack(pop)

int
QUIC_MAIN_EXPORT
main(int argc, char **argv)
{
    const char* Target = "131.107.147.150:32112";
    uint32_t TTL = 1;
    uint32_t Raw = FALSE;

    TryGetValue(argc, argv, "target", &Target);
    TryGetValue(argc, argv, "ttl", &TTL);
    TryGetValue(argc, argv, "raw", &Raw);

    QUIC_ADDR Addr;
    ConvertArgToAddress(Target, 0, &Addr);

    WSADATA WsaData;
    if (WSAStartup(MAKEWORD(2, 2), &WsaData)) {
        printf("WSAStartup failed, 0x%x\n", WSAGetLastError());
        return 1;
    }

    SOCKET Socket = Raw ? socket(AF_INET, SOCK_RAW, 0) : socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (Socket == INVALID_SOCKET) {
        printf("socket failed, 0x%x\n", WSAGetLastError());
        return 1;
    }

    if (setsockopt(Socket, IPPROTO_IP, IP_TTL, (char*)&TTL, sizeof(TTL)) == SOCKET_ERROR) {
        printf("Set IP_TTL failed, 0x%x\n", WSAGetLastError());
        return 1;
    }

    BOOLEAN Enabled = TRUE;
    DWORD BytesReturned;
    if (WSAIoctl(Socket, SIO_UDP_NETRESET, &Enabled, sizeof(Enabled), NULL, 0, &BytesReturned, NULL, NULL) == SOCKET_ERROR) {
        printf("Set SIO_UDP_NETRESET failed, 0x%x\n", WSAGetLastError());
        return 1;
    }

    uint8_t Buffer[] = { 0, 1, 2, 3, 4, 5, 6, 7 };
    printf("Sending...\n");
    if (sendto(Socket, (char*)Buffer, sizeof(Buffer), 0, (sockaddr*)&Addr, sizeof(Addr)) == SOCKET_ERROR) {
        printf("sendto failed, 0x%x\n", WSAGetLastError());
        return 1;
    }

    uint8_t Recv[512] = { 0 };
    QUIC_ADDR RecvAddr;
    int RecvAddrLen = sizeof(RecvAddr);
    printf("Receiving...\n");
    int Count;
    if ((Count = recvfrom(Socket, (char*)Recv, sizeof(Recv), 0, (sockaddr*)&RecvAddr, &RecvAddrLen)) == SOCKET_ERROR) {
        printf("recvfrom failed, 0x%x\n", WSAGetLastError());
        return 1;
    }

    printf("recevied %d bytes:", Count);
    for (int i = 0; i < Count; ++i) {
        if (i % 16 == 0) printf("\n");
        printf("%02hhX", Recv[i]);
    }

    uint8_t* IcmpPayload = Recv + sizeof(IPV4_HEADER) + 8;

    IPV4_HEADER* IPv4 = (IPV4_HEADER*)IcmpPayload;
    UDP_HEADER* UDP = (UDP_HEADER*)(IPv4 + 1);

    char PublicAddr[64] = { 0 };
    ULONG PublicAddrLen = sizeof(PublicAddr);
    RtlIpv4AddressToStringExA(&IPv4->SourceAddress, UDP->uh_sport, PublicAddr, &PublicAddrLen);

    printf("\nPublic Addr: %s", PublicAddr);

    return 0;
}
