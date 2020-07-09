/**************************************************
* File name: sm2_api.h
* Author: Leo Peng
* Date: June 22nd, 2020
* Description: Simple API for SM2
**************************************************/

#ifndef HEADER_SM2_API_H
#define HEADER_SM2_API_H

#ifdef  __cplusplus
  extern "C" {
#endif

// 传入的是 signature
// r[32] 和 s[32] 要从 signature 里面对半拆分。
int sm2_verify(const unsigned char *message,
               const int message_len,
               const unsigned char *id,
               const int id_len,
               const unsigned char *pub_key,
               const unsigned char *r,
               const unsigned char *s);

// 返回 signature，是 r 和 s 的拼接，64 个字节。
char* sm2_sign(const unsigned char *message,
               const int message_len,
               const unsigned char *id,
               const int id_len,
               const unsigned char *pub_key,
               const unsigned char *pri_key);

// 释放 malloc 创建的内存空间。
void sm2_free(char *sig);

#ifdef  __cplusplus
  }
#endif

#endif  /* end of HEADER_SM2_API_H */
