
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <stdio.h>
#include "md5-x86-asm.h"
#include "md5-arm-asm.h"

template<typename HT>
void md5_init(MD5_STATE<HT>* state) {
	state->A = 0x67452301;
	state->B = 0xefcdab89;
	state->C = 0x98badcfe;
	state->D = 0x10325476;
}
#ifdef __AVX512VL__
#include <immintrin.h>
template<>
void md5_init<__m128i>(MD5_STATE<__m128i>* state) {
	state->A = _mm_cvtsi32_si128(0x67452301);
	state->B = _mm_cvtsi32_si128(0xefcdab89);
	state->C = _mm_cvtsi32_si128(0x98badcfe);
	state->D = _mm_cvtsi32_si128(0x10325476);
}
#endif

template<typename HT, void(&fn)(MD5_STATE<HT>*, const void*)>
void md5(MD5_STATE<HT>* state, const void* __restrict__ src, size_t len) {
	md5_init<HT>(state);
	char* __restrict__ _src = (char* __restrict__)src;
	uint64_t totalLen = len << 3; // length in bits
	
	for(; len >= 64; len -= 64) {
		fn(state, _src);
		_src += 64;
	}
	len &= 63;
	
	
	// finalize
	char block[64];
	memcpy(block, _src, len);
	block[len++] = 0x80;
	
	// write this in a loop to avoid duplicating the force-inlined process_block function twice
	for(int iter = (len <= 64-8); iter < 2; iter++) {
		if(iter == 0) {
			memset(block + len, 0, 64-len);
			len = 0;
		} else {
			memset(block + len, 0, 64-8 - len);
			memcpy(block + 64-8, &totalLen, 8);
		}
		
		fn(state, block);
	}
}

bool do_tests(const char* expected, const void* __restrict__ src, size_t len) {
	MD5_STATE<uint32_t> hash;
	md5<uint32_t, md5_block_std>(&hash, src, len);
	if(memcmp(&hash, expected, 16)) return true;
#ifdef PLATFORM_X86
	md5<uint32_t, md5_block_gopt>(&hash, src, len);
	if(memcmp(&hash, expected, 16)) return true;
	md5<uint32_t, md5_block_ghopt>(&hash, src, len);
	if(memcmp(&hash, expected, 16)) return true;
#ifdef __BMI__
	md5<uint32_t, md5_block_ghbmi>(&hash, src, len);
	if(memcmp(&hash, expected, 16)) return true;
#endif
	md5<uint32_t, md5_block_nolea>(&hash, src, len);
	if(memcmp(&hash, expected, 16)) return true;
	md5<uint32_t, md5_block_noleag>(&hash, src, len);
	if(memcmp(&hash, expected, 16)) return true;
	md5<uint32_t, md5_block_noleagh>(&hash, src, len);
	if(memcmp(&hash, expected, 16)) return true;
#ifdef PLATFORM_AMD64
	md5<uint32_t, md5_block_cache4>(&hash, src, len);
	if(memcmp(&hash, expected, 16)) return true;
	md5<uint32_t, md5_block_cache8>(&hash, src, len);
	if(memcmp(&hash, expected, 16)) return true;
	md5<uint32_t, md5_block_cache_gopt>(&hash, src, len);
	if(memcmp(&hash, expected, 16)) return true;
#ifdef __AVX512VL__
	MD5_STATE<__m128i> hashV;
	md5<__m128i, md5_block_avx512>(&hashV, src, len);
	hash.A = _mm_cvtsi128_si32(hashV.A);
	hash.B = _mm_cvtsi128_si32(hashV.B);
	hash.C = _mm_cvtsi128_si32(hashV.C);
	hash.D = _mm_cvtsi128_si32(hashV.D);
	if(memcmp(&hash, expected, 16)) return true;
#endif
#endif
#endif
	
	return false;
}

extern "C" int md5(uint32_t *hash, uint32_t *src, size_t len) {
#ifdef PLATFORM_X86
	md5<uint32_t, md5_block_ghopt>((MD5_STATE<uint32_t>*)hash, src, len);
	return 0;
#ifdef __BMI__
	md5<uint32_t, md5_block_ghbmi>((MD5_STATE<uint32_t>*)hash, src, len);
	return 0;
#endif
	md5<uint32_t, md5_block_noleagh>((MD5_STATE<uint32_t>*)hash, src, len);
	return 0;
#ifdef PLATFORM_AMD64
	md5<uint32_t, md5_block_cache_gopt>((MD5_STATE<uint32_t>*)hash, src, len);
	return 0;
#ifdef __AVX512VL__
	MD5_STATE<__m128i> hashV;
	md5<__m128i, md5_block_avx512>(&hashV, src, len);
	hash[0] = _mm_cvtsi128_si32(hashV.A);
	hash[1] = _mm_cvtsi128_si32(hashV.B);
	hash[2] = _mm_cvtsi128_si32(hashV.C);
	hash[3] = _mm_cvtsi128_si32(hashV.D);
	return 0;
#endif
#endif
#endif
	md5<uint32_t, md5_block_std>((MD5_STATE<uint32_t>*)hash, src, len);
	return 0;		
}
