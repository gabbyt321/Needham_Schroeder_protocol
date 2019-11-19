////////////////////////////////////////////////////////////////////////////////
//
//  File          : cmpsc443_ns_client.c
//  Description   : This is the client side of the Needham Schroeder 
//                  protocol, and associated main processing loop.
//
//   Author        : Gabriella Tolotta
//   Last Modified : FILL IN
//

// Includes
#include <unistd.h>
#include <cmpsc311_log.h>
#include <cmpsc311_network.h>
#include <string.h>
#include <arpa/inet.h>
#include <gcrypt.h>

// Project Include Files
#include <cmpsc443_ns_proto.h>
#include <cmpsc443_ns_util.h>
#include <cmpsc311_util.h>

// Defines
#define NS_ARGUMENTS "h"
#define USAGE \
	"USAGE: cmpsc443_ns_client [-h]\n" \
	"\n" \
	"where:\n" \
	"    -h - help mode (display this message)\n" \
	"\n" \

// Functional Prototypes
int ns_client( void );

//
// Functions

////////////////////////////////////////////////////////////////////////////////
//
// Function     : main
// Description  : The main function for the Needam Schroeder protocol client
//
// Inputs       : argc - the number of command line parameters
//                argv - the parameters
// Outputs      : 0 if successful, -1 if failure

int main( int argc, char *argv[] )
{
	// Local variables
	int ch;

	// Process the command line parameters
	while ((ch = getopt(argc, argv, NS_ARGUMENTS)) != -1) {

		switch (ch) {
		case 'h': // Help, print usage
			fprintf( stderr, USAGE );
			return( -1 );

		default:  // Default (unknown)
			fprintf( stderr, "Unknown command line option (%c), aborting.\n", ch );
			return( -1 );
		}
	}

	// Create the log, run the client
    initializeLogWithFilehandle(STDERR_FILENO);
    enableLogLevels(LOG_INFO_LEVEL);
	ns_client();

	// Return successfully
	return( 0 );
}

////////////////////////////////////////////////////////////////////////////////
// Helper Functions

// create the 4 byte (32 bit) header
uint32_t create_header(uint16_t payload_length, message_type_t message_type){

	payload_length = htons((uint16_t)payload_length); // network byte order 
	message_type = htons((uint16_t)message_type);
	uint32_t header = 0;
	header = message_type << 16;  
	
	header = header | payload_length;

	/*

	logMessage(LOG_INFO_LEVEL, "Payload Length: %u, ", payload_length);
	logMessage(LOG_INFO_LEVEL, "Message Type: %u, ", message_type);
	logMessage(LOG_INFO_LEVEL, "Name: %u, ", header);*/
	return header;  


}


////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////
//
// Function     : ns_client
// Description  : The client function for the Needam Schroeder protocol server
//
// Inputs       : none
// Outputs      : 0 if successful, -1 if failure

int ns_client( void ) {
	
	// establish the server connection 
	unsigned char * ip1= "127.0.0.1";
	int socket = cmpsc311_client_connect(ip1,NS_SERVER_PROTOCOL_PORT );
	if (socket == -1) return -1; // could not connect to server

	// execute protocol 

	//********************Message # 1********************//
	// create message contents:
	uint16_t msg_1_len = 40;
	uint32_t msg1_header = create_header(msg_1_len, NS_TKT_REQ);

	// message is 64 bits + 16 bytes + 16 bytes = 40 bytes
	unsigned char* message1 = malloc(44); 

	tkt_req_t payload1;
	memset(&payload1.A, 0, 16);
	memset(&payload1.B, 0, 16);

	memcpy(&payload1.A, &NS_ALICE_IDENTITY, sizeof(NS_ALICE_IDENTITY));
	memcpy(&payload1.B, &NS_BOB_IDENTITY, sizeof(NS_BOB_IDENTITY)); 
	
	createNonce(&payload1.N1);
	htonll64(payload1.N1);

	logBufferMessage(LOG_OUTPUT_LEVEL, "ORIGINAL nonce1 network byte order ", &payload1.N1, 8);
	logBufferMessage(LOG_OUTPUT_LEVEL, "MESAGE1-- ALICE IDENTITY   ", &payload1.A,16);
	logBufferMessage(LOG_OUTPUT_LEVEL, "MESAGE1-- BOB IDENTITY   ", &payload1.B,16);

	memcpy(message1, &msg1_header, 4);
	memcpy(message1 + 4, &payload1.N1, 8);
	memcpy(message1 + 12, &payload1.A, 16);
	memcpy(message1 + 28, &payload1.B, 16);

	if (cmpsc311_send_bytes( socket, 44, message1) == -1) return -1;
	free(message1);

	//********************Message # 2********************//
	// get ticket response 

	// read bytes into buffer h2
	unsigned char *h2 = malloc(4);
	cmpsc311_read_bytes(socket, 4, h2); 

	// parse header
	// first two bytes are length of payload
	uint16_t length2;
	memcpy(&length2, h2, 2);
	length2 = htons((uint16_t) length2);

	uint16_t type2;
	memcpy(&type2, h2 + 2, 2); 
	type2 = htons((uint16_t)type2);

	logMessage(LOG_INFO_LEVEL, "Payload Length : %u, ", length2);
	logMessage(LOG_INFO_LEVEL, "Message Type: %u, ", type2);
	free(h2);

	// read bytes into message 2 buffer
	unsigned char *message2 = malloc(length2);
	cmpsc311_read_bytes(socket, length2, message2); 
	logBufferMessage(LOG_OUTPUT_LEVEL, "second message  ", message2, length2);

	// get initialization vector
	void * init_vect2 = malloc(16);
	memcpy(init_vect2, message2, 16); // first 16 bytes of message are initializaiton vector 


	//SETUP GCRYPT INFORMATION *******************************************************
	 // 128 bit aes cnecryption 
	 // cipher mode = cipher block chaining mode

	gcry_cipher_hd_t info;
	gcry_cipher_open(&info, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CBC, 0 );
	

	//encrypted buffer starts at 16+2
	// get keys for alice and bob Ka and Kb
	ns_key_t kalice;
	makeKeyFromPassword(NS_ALICE_PASSWORD , kalice);
	gcry_cipher_setkey(info, kalice, 16);
	gcry_cipher_setiv(info, init_vect2, 16); 

	// 96 = payload length - initialization vector length - length bytes

	//decrypt buffer with kalice
	char * encrypted2 = malloc(96);
	memcpy(encrypted2, message2 + 18, 96); // offset initialization vector and length 
	logBufferMessage(LOG_OUTPUT_LEVEL, "encrypted message  ", encrypted2, 96);

	gcry_cipher_decrypt(info, encrypted2, 96, NULL, 0);
	logBufferMessage(LOG_OUTPUT_LEVEL, "decrypted message  ", encrypted2, 96);


	// setup payload2 for ticket response
	tkt_res_t payload2; 

	memcpy(&payload2.N1, encrypted2, 8); // 8 byte nonce
	memcpy(&payload2.B, encrypted2 + 8, 16); // 16 byte identity of bob
	memcpy(&payload2.Kab, encrypted2 + 24, 16); // 16 byte session key


	// get 2 byte length for entire ticket w/ initialization vector
	void *total_length_ticket = malloc(2); 
	memcpy(total_length_ticket, encrypted2 + 40, 2); 
	logBufferMessage(LOG_OUTPUT_LEVEL, "Payload 2 TOTAL  length in network byte order  ", total_length_ticket, 2);

	void *init_vect_ticket = malloc(16);
	memcpy(init_vect_ticket, encrypted2 + 42, 16);

	memcpy(&payload2.ticket.length, encrypted2+ 58, 2); //length of ticket in network byte order
	logBufferMessage(LOG_OUTPUT_LEVEL, "Payload 2 Ticket Length in network byte order  ", &payload2.ticket.length, 2);
	memcpy(&payload2.ticket.data, encrypted2+60, 32);

	//logBufferMessage(LOG_OUTPUT_LEVEL, "Payload 2 Ticket Data  ", &payload2.ticket.data, 2);
	logBufferMessage(LOG_OUTPUT_LEVEL, "nonce1  ", &payload2.N1, 8);

	// free up some memory 
	free(encrypted2);

	gcry_cipher_close(info); // close cipher 

	//********************Message # 3********************//
	// Service Request
	// Create nonce2

	svc_req_t payload3; 
	memset(&payload3.A, 0, 16);
	memcpy(&payload3.A, &NS_ALICE_IDENTITY, sizeof(NS_ALICE_IDENTITY));
	memcpy(&payload3.B, &payload2.B, 16);
	memcpy(&payload3.ticket.length, &payload2.ticket.length,2);
	memcpy(&payload3.ticket.data, &payload2.ticket.data, 32); 

	logBufferMessage(LOG_OUTPUT_LEVEL, "MESAGE3-- ALICE IDENTITY   ", &payload3.A,16);
	logBufferMessage(LOG_OUTPUT_LEVEL, "MESAGE3-- BOB IDENTITY   ", &payload3.B,16);


	createNonce(&payload3.N2);
	htonll64(payload3.N2); //convert to network byte order then encrypt 

	//SETUP GCRYPT INFORMATION *******************************************************
	gcry_cipher_hd_t info1;
	gcry_cipher_open(&info1, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CBC, 0 );
	gcry_cipher_setkey(info1, &payload2.Kab, 16);

	// Create initvect
	char *init_vect3 = malloc(16);
	getRandomData( init_vect3, 16 );
	gcry_cipher_setiv(info1, init_vect3, 16); 

	//encrypt nonce with kab
	char *encrypted_n2 = malloc(16);

	// padd with zeroes
	memset(encrypted_n2, 0, 16);
	memcpy(encrypted_n2, &payload3.N2, 8);
	gcry_cipher_encrypt(info1, encrypted_n2, 16, NULL, 0);

	// create header FIXXXXXX
	int payload_length3 = 118;
	uint32_t header3 = create_header(payload_length3, NS_SVC_REQ);

	uint16_t length_nonce_encrypt = 8;
	length_nonce_encrypt = htons(length_nonce_encrypt);	

	logBufferMessage(LOG_OUTPUT_LEVEL, "Length of encrypted nonce message 3 ", &length_nonce_encrypt,2);

	
	// setup message 3
	unsigned char* message3 = malloc(122); // payload plus header 

	// 122 bytes = 4 + 16 + 16 + 2 + 16 + 2 +  32 + 16 + 2 + 16

	memcpy(message3, &header3, 4);// 4 byte header correct
	memcpy(message3 + 4, &payload3.A , 16); // correct
	memcpy(message3+ 20, &payload3.B , 16);  // correct
	memcpy(message3 + 36, total_length_ticket, 2);
	memcpy(message3 + 38, init_vect_ticket, 16); 
	memcpy(message3 + 54, &payload3.ticket.length, 2); 
	memcpy(message3 + 56, &payload3.ticket.data, 32);
	memcpy(message3+ 88, init_vect3, 16);
	memcpy(message3+104, &length_nonce_encrypt, 2);
	memcpy(message3+106, encrypted_n2, 16); 
	
	if (cmpsc311_send_bytes( socket, 122, message3) == -1) return -1;

	gcry_cipher_close(info1); // close cipher 
	//********************Message # 4********************//
	// Service Response 
	// get header 

	unsigned char* header4= malloc(4);
	cmpsc311_read_bytes( socket, 4, header4);

	// parse header
	// first two bytes are length of payload
	uint16_t length4;
	memcpy(&length4, header4, 2);
	length4 = htons((uint16_t) length4);

	logMessage(LOG_INFO_LEVEL, "Payload Length message 4 : %u, ", length4);
	// 34 byte payload = 16 byte initialization vector + 2 byte length + 16 byte encrypted stuff. 

	// get initialization vector
	char *init_vect4 = malloc(16);
	cmpsc311_read_bytes( socket, 16, init_vect4);

	// get plaintext length 
	char *plaintext_length4 = malloc(2);
	cmpsc311_read_bytes(socket, 2, plaintext_length4);

	// get encrypted block 
	char *encrypted4 = malloc(16);
	cmpsc311_read_bytes(socket, 16, encrypted4);

	//SETUP GCRYPT INFORMATION *******************************************************
	gcry_cipher_hd_t info4;
	gcry_cipher_open(&info4, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CBC, 0 );
	gcry_cipher_setkey(info4, &payload2.Kab, 16);
	gcry_cipher_setiv(info4, init_vect4, 16); 

	logBufferMessage(LOG_OUTPUT_LEVEL, "Encrypted message ", encrypted4, 16);
	gcry_cipher_decrypt(info4, encrypted4, 16, NULL, 0);
	logBufferMessage(LOG_OUTPUT_LEVEL, "Decrypted message ", encrypted4, 16);

	// Service resposne
	svc_res_t payload4; 
	memcpy(&payload4.N2, encrypted4, 8); // without the minus 1
	memcpy(&payload4.N3, encrypted4+8, 8); 
	logBufferMessage(LOG_OUTPUT_LEVEL, "Original Nonce 3 received from encrypted message 4", &payload4.N3, 8);

	//convert nonce 3 to host byte order
	payload4.N3 = htonll64(payload4.N3);

	gcry_cipher_close(info4);

	//********************Message # 5********************//
	// Service Acknowledgement 

	// setup struct; 
	svc_ack_t payload5;
	memcpy(&payload5.N3, &payload4.N3, 8); // nonce is 8 bytes 
	
	payload5.N3 = payload5.N3 - 0x01; //(N3 - 1)
	payload5.N3 = htonll64(payload5.N3);
	logBufferMessage(LOG_OUTPUT_LEVEL, "ATTEMPT SUBTRACTING 1 ", &payload5.N3, 8);


	//Setup initialization vector 5
	char *init_vect5 = malloc(16);
	getRandomData( init_vect5, 16 );

	// Setup total ticket length 
	uint16_t length_nonce3_encrypt = 8;
	length_nonce3_encrypt = htons(length_nonce3_encrypt);

	//SETUP GCRYPT INFORMATION *******************************************************
	gcry_cipher_hd_t info5;
	gcry_cipher_open(&info5, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CBC, 0 );
	gcry_cipher_setkey(info5, &payload2.Kab, 16);
	gcry_cipher_setiv(info5, init_vect5, 16); 

	// setup encrypted block 
	char *encrypted5 = malloc(16);
	//pad nonce
	memset(encrypted5, 0, 16);
	memcpy(encrypted5, &payload5.N3, 8); 
	gcry_cipher_encrypt(info5, encrypted5, 16, NULL, 0);

	// setup header
	uint32_t header5 = create_header(34, NS_SVC_ACK);


	// copy data and send 
	unsigned char* message5 = malloc(38);
	memcpy(message5, &header5, 4);
	memcpy(message5 +4, init_vect5, 16); 
	memcpy(message5 + 20, &length_nonce3_encrypt, 2);
	memcpy(message5 +22 , encrypted5, 16);

	if (cmpsc311_send_bytes( socket, 38, message5) == -1) return -1;
	gcry_cipher_close(info5);

	//********************Message # 6********************//
	// Data request 

	// Read header 
	unsigned char* header6= malloc(4);
	cmpsc311_read_bytes( socket, 4, header6);

	// parse header
	// first two bytes are length of payload
	uint16_t length6;
	memcpy(&length6, header6, 2);
	length6 = htons((uint16_t) length6);
	logMessage(LOG_INFO_LEVEL, "Payload Length message 6 : %u, ", length6);
	// length = 146 bytes (not including header)

	// get initialization vector 6
	char *init_vect6 = malloc(16);
	cmpsc311_read_bytes( socket, 16, init_vect6);

	// get length of plaintext data 
	char *plaintext_length6 = malloc(2); 
	cmpsc311_read_bytes(socket, 2, plaintext_length6);
	logBufferMessage(LOG_OUTPUT_LEVEL, "Length of plaintext data ", plaintext_length6, 2); // 128

	uint8_t data_sent[128];
	cmpsc311_read_bytes(socket, 128, &data_sent);

	//SETUP GCRYPT INFORMATION *******************************************************
	gcry_cipher_hd_t info6;
	gcry_cipher_open(&info6, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CBC, 0 );
	gcry_cipher_setkey(info6, &payload2.Kab, 16);
	gcry_cipher_setiv(info6, init_vect6, 16); 
	gcry_cipher_decrypt(info6, &data_sent, 128, NULL, 0);

	gcry_cipher_close(info6); // close cipher

	//********************Message # 7********************//
	// data response

	// xor data with 1011 0110
	// 11 and 6
	// 0xb6
	// update data to send
	uint8_t xor_part = 0xb6;
	int i = 0; 

	for(i = 0; i<128; i++){
		data_sent[i]  = data_sent[i]^xor_part;
	}

	//Setup initialization vector 5
	char *init_vect7 = malloc(16);
	getRandomData( init_vect7, 16 );


	 //SETUP GCRYPT INFORMATION *******************************************************
	gcry_cipher_hd_t info7;
	gcry_cipher_open(&info7, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CBC, 0 );
	gcry_cipher_setkey(info7, &payload2.Kab, 16);
	gcry_cipher_setiv(info7, init_vect7, 16); 
	
	gcry_cipher_encrypt(info7, &data_sent, 128, NULL, 0);

	//payload length = 128+2+16 = 146
	uint16_t payload_length7 = 146; 

	//setup header
	uint32_t header7 = create_header(payload_length7, NS_DAT_RES);
	unsigned char* message7 = malloc(150);
	
	// Setup total ticket length 
	uint16_t length7= 128;
	length7 = htons(length7);



	memcpy(message7, &header7, 4);

	memcpy(message7+4, init_vect7, 16);
	memcpy(message7+20, &length7, 2);
	memcpy(message7+22, &data_sent, 128);

	if (cmpsc311_send_bytes( socket, 150, message7) == -1) return -1;

	gcry_cipher_close(info7); // close cipher


	if ( (cmpsc311_close(socket ))== -1) return -1;


	// Return successfully
	return(0);
}