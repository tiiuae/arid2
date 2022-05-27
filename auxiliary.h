#ifndef _AUXILIARY_
#define _AUXILIARY_
    #include <iostream>
    #include <fstream>
    #include <sstream>
    #include <string>
    #include <iomanip>
    #include <string.h>
    #include <pbc/pbc.h>
    #include <unistd.h>
    #include <cstdlib>
    #include <tins/tins.h>
    #include "sha1/sha1.h"
    #include "base58/base58.h"

using namespace std;
class Auxiliary
{
public:
    static string  Hash_g_R(element_t g, element_t R);
    static void    Hash_T1_T2_T3(element_t res,element_t T1,element_t T2,element_t T3);
    static void    Hash_C(element_t res,element_t R1,element_t R2,element_t R3,element_t R4, element_t R5,element_t g,element_t gt,element_t X, element_t Y, element_t h,element_t y1, element_t y2, element_t y3, char* mes, int len_mes);
    static string  Element_to_BASE_58(element_t elem);
    static void    Element_from_BASE_58(element_t elem,string elem_base58);
    static string  SignatureToString(element_t c,element_t Sp,element_t Sm,element_t Sv,element_t T1,element_t T2,element_t T3,element_t T4,element_t T5,element_t T6,element_t T7);
    static void    NextString(string & str,element_t elem);
    static void    SignatureFromString(string signature, element_t c_H,element_t Sp,element_t Sm,element_t Sv,element_t T1,element_t T2,element_t T3,element_t T4,element_t T5,element_t T6,element_t T7);
    
    static string  GroupPublicKeyToString(element_t g_w,element_t gt_w,element_t X_w,element_t Y_w,element_t h_w,element_t y1_w,element_t y2_w,element_t y3_w);
    static void    SetPublicKey(string gpk, element_t g_r, element_t gt_r, element_t X_r, element_t Y_r, element_t h_r, element_t y1_r, element_t y2_r, element_t y3_r);
    
    static string  SecretIssuingKeyToString(element_t x, element_t y);
    static void    SetSecretIssuingKey(string ik, element_t x, element_t y);
    
    static string  OpeningKeyToString(element_t x1, element_t x2, element_t x3, element_t x4, element_t x5);
    static void    SetOpeningKey(string ok, element_t x1, element_t x2, element_t x3, element_t x4, element_t x5);

    static string  SecretSigningKeyToString(element_t ki, element_t ai, element_t bi, element_t ci);
    static void    SetSecretSigning(string gsk, element_t ki, element_t ai, element_t bi, element_t ci);
    
    static string  RegisterUserToString(element_t Pi1, element_t Pi2);
    static vector<unsigned char> intToBytes(int paramInt);
};
#endif