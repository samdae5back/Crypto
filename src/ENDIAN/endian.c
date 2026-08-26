#include "ENDIAN.h"
uint16_t ENDIAN_LOAD16_LE(const uint8_t *p){return (uint16_t)p[0]|((uint16_t)p[1]<<8);}
uint32_t ENDIAN_LOAD32_LE(const uint8_t *p){return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);}
uint64_t ENDIAN_LOAD64_LE(const uint8_t *p){return (uint64_t)ENDIAN_LOAD32_LE(p)|((uint64_t)ENDIAN_LOAD32_LE(p+4)<<32);}
uint16_t ENDIAN_LOAD16_BE(const uint8_t *p){return ((uint16_t)p[0]<<8)|(uint16_t)p[1];}
uint32_t ENDIAN_LOAD32_BE(const uint8_t *p){return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|(uint32_t)p[3];}
uint64_t ENDIAN_LOAD64_BE(const uint8_t *p){return ((uint64_t)ENDIAN_LOAD32_BE(p)<<32)|(uint64_t)ENDIAN_LOAD32_BE(p+4);}
void ENDIAN_STORE16_LE(uint8_t *p,uint16_t x){p[0]=(uint8_t)x;p[1]=(uint8_t)(x>>8);}
void ENDIAN_STORE32_LE(uint8_t *p,uint32_t x){p[0]=(uint8_t)x;p[1]=(uint8_t)(x>>8);p[2]=(uint8_t)(x>>16);p[3]=(uint8_t)(x>>24);}
void ENDIAN_STORE64_LE(uint8_t *p,uint64_t x){ENDIAN_STORE32_LE(p,(uint32_t)x);ENDIAN_STORE32_LE(p+4,(uint32_t)(x>>32));}
void ENDIAN_STORE16_BE(uint8_t *p,uint16_t x){p[0]=(uint8_t)(x>>8);p[1]=(uint8_t)x;}
void ENDIAN_STORE32_BE(uint8_t *p,uint32_t x){p[0]=(uint8_t)(x>>24);p[1]=(uint8_t)(x>>16);p[2]=(uint8_t)(x>>8);p[3]=(uint8_t)x;}
void ENDIAN_STORE64_BE(uint8_t *p,uint64_t x){ENDIAN_STORE32_BE(p,(uint32_t)(x>>32));ENDIAN_STORE32_BE(p+4,(uint32_t)x);}
