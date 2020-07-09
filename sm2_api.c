#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sm2_create_key_pair.h"
#include "sm2_sign_and_verify.h"
#include "sm2_api.h"

void to_hex(unsigned char *p_str, unsigned char *p_hex, int size) {
  size_t i;
  for (i = 0; i < size; i++) {
    sscanf(p_str, "%2hhx", p_hex + i);
    p_str += 2;
  }
}

const int PUBKEY_SIZE = 65;
const int PRIKEY_SIZE = 32;
const int SIGNATURE_SIZE = 64;
const int COORDINATE_SIZE = 32;

int sm2_verify(const unsigned char *message,
            const int message_len,
            const unsigned char *id,
            const int id_len,
            const unsigned char *pub_key,
            const unsigned char *r,
            const unsigned char *s) {
  int error_code;
	SM2_KEY_PAIR key_pair;
	SM2_SIGNATURE_STRUCT sm2_sig;

	unsigned char *p_str_pubkey = pub_key;
  unsigned char hex_pubkey[PUBKEY_SIZE];
  unsigned char *p_hex_pubkey = hex_pubkey;

  to_hex(p_str_pubkey, p_hex_pubkey, PUBKEY_SIZE);
  memcpy(key_pair.pub_key, p_hex_pubkey, PUBKEY_SIZE);

	unsigned char *p_str_r = r;
	unsigned char *p_str_s = s;

	unsigned char hex_r[COORDINATE_SIZE];
	unsigned char *p_hex_r = hex_r;

	unsigned char hex_s[COORDINATE_SIZE];
	unsigned char *p_hex_s = hex_s;

	to_hex(p_str_r, p_hex_r, COORDINATE_SIZE);
	to_hex(p_str_s, p_hex_s, COORDINATE_SIZE);

	memcpy(sm2_sig.r_coordinate, hex_r, COORDINATE_SIZE);
	memcpy(sm2_sig.s_coordinate, hex_s, COORDINATE_SIZE);

	if ( error_code = sm2_verify_sig(message,
		                         message_len,
					 id,
					 id_len,
					 key_pair.pub_key,
					 &sm2_sig) )
	{
	   return error_code;
	}

	return 0;
}

char* sm2_sign(const unsigned char *message,
               const int message_len,
               const unsigned char *id,
               const int id_len,
               const unsigned char *pub_key,
               const unsigned char *pri_key) {
	int error_code;
	SM2_KEY_PAIR key_pair;
	SM2_SIGNATURE_STRUCT sm2_sig;

	unsigned char *p_str_pubkey = pub_key;
  unsigned char hex_pubkey[PUBKEY_SIZE];
  unsigned char *p_hex_pubkey = hex_pubkey;

  to_hex(p_str_pubkey, p_hex_pubkey, PUBKEY_SIZE);
  memcpy(key_pair.pub_key, p_hex_pubkey, PUBKEY_SIZE);

	unsigned char *p_str_prikey = pri_key;
	unsigned char hex_prikey[PRIKEY_SIZE];
	unsigned char *p_hex_prikey = hex_prikey;

	to_hex(p_str_prikey, p_hex_prikey, PRIKEY_SIZE);
	memcpy(key_pair.pri_key, p_hex_prikey, PRIKEY_SIZE);

	if ( error_code = sm2_sign_data(message,
		message_len,
		id,
		id_len,
		key_pair.pub_key,
		key_pair.pri_key,
		&sm2_sig) )
	{
		return NULL;
	}

	unsigned char sig_hex[SIGNATURE_SIZE];
	memcpy(sig_hex, sm2_sig.r_coordinate, COORDINATE_SIZE);
	memcpy(sig_hex + COORDINATE_SIZE, sm2_sig.s_coordinate, COORDINATE_SIZE);

	unsigned char sig_str[SIGNATURE_SIZE * 2 + 1];
	char *sig_ptr = (char *) malloc((SIGNATURE_SIZE * 2 + 1) * sizeof(unsigned char));

	size_t i;
	for (i = 0; i < SIGNATURE_SIZE; i++) {
		sprintf(&sig_str[i * 2], "%02X", sig_hex[i]);
	}
	sig_str[SIGNATURE_SIZE * 2] = '\0';

	memcpy(sig_ptr, sig_str, SIGNATURE_SIZE * 2 + 1);

	return sig_ptr;
}

// 释放 signature 占用的内存。
void sm2_free(char *sig) {
	free(sig);
}
