
#include <stdint.h>

#define TRUE   1
#define FALSE  0
#define NOFLAG 0
#define TIME_BUFFER_SIZE 128
#define SSID_BUFFER_SIZE 32
#define MAC_BUFFER_SIZE  32

// Needs to be sized for arbitrary protocols
#define PACKET_BUFFER_SIZE  65536

// 802.11 frame offsets
#define FRAME_CTL_OFFSET 26
#define SSID_LEN_OFFSET  51
#define SSID_CHR_OFFSET  52
#define MAC_ADDR_OFFSET  36
#define DEST_ADDR_OFFSET 42
#define RSSI_OFFSET      22
#define FREQ_OFFSET      19

typedef struct _req *Request;

typedef struct _req{
    // String timestamp of
    char ts[TIME_BUFFER_SIZE];
    // Device MAC
    char deviceMAC[MAC_BUFFER_SIZE];
    // Requesting station
    char ssid[SSID_BUFFER_SIZE];
    // On frequency
    uint16_t frequency;
    // With signal strength
    int8_t rssi;
    float distance;
} req;

// The main parser
Request parseRaw( uint8_t *buff, uint16_t buffSize );
// A boolean for the destination MAC

int isBroadcast( uint8_t *buff );
// Handy for conversions
uint64_t macU8ToU64( uint8_t *mac );
// A rough distance using uncalibrated FSPL equations
float signalToDistance( int8_t rssi, uint16_t frequency );
