#ifndef CMPSC443_UTIL_INCLUDED
#define CMPSC443_UTIL_INCLUDED

////////////////////////////////////////////////////////////////////////////////
//

// Includes
#include <cmpsc443_ns_proto.h>

/**
 * Function      : createNonce
 * Description   : Creates a random nonce using gcrypt
 * 
 * Inputs        : nonce - Pointer to the nonce to populate with random data
 */
int createNonce(ns_nonce_t* nonce);

/**
 * Function      : makeKeyFromPassword
 * Description   : Derives a key from an input password
 * 
 * Inputs        : password - The password to use for key generation
 *                 key      - The key to populate wit hthe derived key
 */
int makeKeyFromPassword(char *password, ns_key_t key);

#endif
