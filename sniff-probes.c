
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <ctype.h>
#include <string.h>
#include <math.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/ip.h>
#include "sniff-probes.h"

int main( int argc, char **argv ) {

    // At the moment, the monitor interface
    // is provided by the user.
    char *interface = "";
    if( argc == 2 ) {
        interface = argv[1];
    } else {
        // Give a little help.
        fprintf(stderr, "Provide exactly one argument, "
                        "the monitor interface dev name.\n"
                        "e.g\n"
                        "./sniffProbes wlanXmon\n");
        fflush( stderr );
        return EXIT_FAILURE;
    }

    // Create a buffer for 802.11 packets
    uint8_t pktBuff[ PACKET_BUFFER_SIZE ];

    // Setup a socket to sniff all protocols on the interface
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(sock < 0){
        fprintf(stderr, "[sniffProbes] Error creating socket, "
                        "are you running as root?\n");
        fflush( stderr );
        return EXIT_FAILURE;
    }

    // Setup interface - SECURITY RISK - constrain the size *interface
    struct ifreq interfaceOpts;
    strncpy(interfaceOpts.ifr_name, interface, strlen( interface ));
    ioctl(sock, SIOCGIFFLAGS, &interfaceOpts);

    // Ensure promiscuous mode is set - not really needed within spec
    interfaceOpts.ifr_flags |= IFF_PROMISC;
    int setOptsVal = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
                                &interfaceOpts, sizeof(interfaceOpts));
    if(setOptsVal < 0) {
        fprintf( stderr, "[sniffProbes] Error setting promiscuous mode on "
                         "interface: %s\n", interface );
        fflush(  stderr );
        return EXIT_FAILURE;
    }
    
    setOptsVal = setsockopt( sock, SOL_SOCKET, SO_BINDTODEVICE,
                             interface, strlen(interface) );
    if(setOptsVal < 0) {
        fprintf( stderr, "[sniffProbes] Error binding to specified "
                         "interface: %s\n", interface );
        fflush(  stderr );
        return EXIT_FAILURE;
    }

    // Main loop
    while(TRUE) {
        // Receive any data from the broadcast medium (802.11)
        int recvDataSize = recvfrom( sock, pktBuff, PACKET_BUFFER_SIZE,
                                     NOFLAG, NULL, NULL);
        if( recvDataSize ) {
            // Send off to parser
            Request request = parseRaw(pktBuff, recvDataSize);

            // If it was a probe request
            if( request != NULL ){
                // Print in an easily filtered format for now
                fprintf(stdout, "%s|%s|%ddBm|%.02fm\n",
                                request->deviceMAC,
                                request->ssid,
                                request->rssi,
                                request->distance);
                fflush( stdout );
            }
            free( request);
        }
    }
    return EXIT_SUCCESS;
}


/*
Need to add check for probe request frames
*/
Request parseRaw( uint8_t *buff, uint16_t buffSize ) {
    // Get the frame protocol out
    int16_t frameProtocol = (buff[FRAME_CTL_OFFSET] & 0xF0) >> 4;
    // add 802 frame check
    // if( isBroadcast( &buff[DEST_ADDR_OFFSET]) ){
        // Begin decoding the frame
        int i, validSSID;
        validSSID = TRUE;
        // Throw a new request onto the heap
        Request request = malloc( sizeof( Request ) );
        // Preformat the SSID with NULL chars
        memset(request->ssid, '\0', SSID_BUFFER_SIZE);
        memset(request->deviceMAC, '\0', 16);
        // Check the SSID isn't blank or ovrflw
        uint8_t SSIDlen = buff[SSID_LEN_OFFSET];
	      if( SSIDlen >= 0 && SSIDlen <= SSID_BUFFER_SIZE ) {
            if( SSIDlen == 0 ) {
                strcpy(request->ssid, "BROADCAST PROBE");
            } else {
	        // Copy SSID into request
                for(i = 0; i < SSIDlen; i++){
                    // If it's a printable char
                    if( isprint(buff[SSID_CHR_OFFSET + i]) && validSSID ) {
                        request->ssid[i] = buff[SSID_CHR_OFFSET + i];
                    // Otherwise it's something interesting. Seen non ASCII
                    // SSIDs in the wild.
                    } else {
                        // Convert it to a '\xNN' string rep
                        char hexByte[5];
                        snprintf(&hexByte[0], 5, "\\x%02X",
                                (unsigned char)buff[SSID_CHR_OFFSET + i]);
                        // Set the SSID to printable HEX
                        request->ssid[i] = hexByte[0];
                        request->ssid[i+1] = hexByte[1];
                        request->ssid[i+2] = hexByte[2];
                        request->ssid[i+3] = hexByte[3];
                        // Kick i fwd a few spots
                        i+=3;
                        validSSID = FALSE;
                    }
		           }
            }
            // Now get client MAC as uint64
            uint64_t longMac = macU8ToU64( &buff[ MAC_ADDR_OFFSET ] );
            // Make a HEX string from it
            snprintf(request->deviceMAC, 32, "%012" PRIX64, longMac);
            // Set the RSSI (dBm)
            request->rssi = buff[ RSSI_OFFSET ] - 0xFF;
            // Set the frequency - not that interesting, doppler would be nice
            request->frequency  = ( buff[ FREQ_OFFSET ] ) << 8;
            request->frequency |= ( buff[ FREQ_OFFSET+1 ] );
            // set the distance estimate - rough, but still informative
            request->distance = signalToDistance(request->rssi,
                                                 request->frequency);
            return request;
        } else {
            // SSID length was outside spec
            return NULL;
        }
    // } else {
    //     // Frame protocol other than probe request
    //     return NULL;
    // }
}

/*
Add broadcast MAC check
*/
int isBroadcast( uint8_t *buff ) {
  // FIX ME
  return TRUE;
}

/*
Convert 64 bit unsigned int MAC to string
*/
uint64_t macU8ToU64( uint8_t *mac ) {
    uint64_t macint;
    // MAC bytes into a long
    macint =  (uint64_t)mac[0] << (8*5);
    macint |= (uint64_t)mac[1] << (8*4);
    macint |= (uint64_t)mac[2] << (8*3);
    macint |= (uint64_t)mac[3] << (8*2);
    macint |= (uint64_t)mac[4] <<  8;
    macint |= (uint64_t)mac[5];
    return macint;
}

float signalToDistance( int8_t RSSI, uint16_t frequency ) {
    //float distance = (27.55-RSSI-(20*log10(frequency)))/20.00;
    //return (float)pow(10, distance);
    float exp = 1+(-(RSSI)-40.09)/20;
    return pow(10, exp);
}
