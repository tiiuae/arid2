// Copyright (c) 2009 - 2010 Satoshi Nakamoto
// Copyright (c) 2009 - 2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Why base-58 instead of standard base-64 encoding?
 * - Don't want 0OIl characters that look the same in some fonts and
 *      could be used to create visually identical looking data.
 * - A string with non-alphanumeric characters is not as easily accepted as input.
 * - E-mail usually won't line-break if there's no punctuation to break at.
 * - Double-clicking selects the whole string as one word if it's all alphanumeric.
 */

#ifndef _BASE_58_
#define _BASE_58_

#include <assert.h>
#include <string.h>
#include <vector>
#include <string>

/** All alphanumeric characters except for "0", "I", "O", and "l" */
static const char* pszBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

std::string EncodeBase58(const unsigned char* pbegin, const unsigned char* pend);
bool DecodeBase58(const char* psz, std::vector<unsigned char>& vch);

std::string EncodeBase58(void* data, int len);
bool DecodeBase58(std::string code, void* data, int len);

#endif //_BASE_58_