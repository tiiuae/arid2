#include "auxiliary.h"

string Auxiliary::Hash_g_R(element_t g, element_t R)
{
    int len1 = element_length_in_bytes(g);
    int len2 = len1 + element_length_in_bytes(R);

    unsigned char *buf = new unsigned char[len2];
    element_to_bytes(buf, g);
    element_to_bytes(buf + len1, R);

    // SHA1
    unsigned char h[20];
    char hex[41];
    sha1::calc(buf, len2, h);
    sha1::toHexString(h, hex);
    string hash(hex);
    delete[] buf;
    return hash;
}

void Auxiliary::Hash_T1_T2_T3(element_t res, element_t T1, element_t T2, element_t T3)
{
    int len1 = element_length_in_bytes(T1);
    int len2 = len1 + element_length_in_bytes(T2);
    int len3 = len2 + element_length_in_bytes(T3);
    unsigned char *buf = new unsigned char[len3];
    element_to_bytes(buf, T1);
    element_to_bytes(buf + len1, T2);
    element_to_bytes(buf + len2, T3);
    unsigned char hash[20];
    sha1::calc(buf, len3, hash);
    element_from_hash(res, (void *)hash, 20);
    delete[] buf;
}

void Auxiliary::Hash_C(element_t res, element_t R1, element_t R2, element_t R3, element_t R4, element_t R5, element_t g, element_t gt, element_t X, element_t Y, element_t h, element_t y1, element_t y2, element_t y3, char *mes, int len_mes)
{
    int len1 = element_length_in_bytes(R1);
    int len2 = len1 + element_length_in_bytes(R2);
    int len3 = len2 + element_length_in_bytes(R3);
    int len4 = len3 + element_length_in_bytes(R4);
    int len5 = len4 + element_length_in_bytes(R5);
    int len6 = len5 + element_length_in_bytes(g);
    int len7 = len6 + element_length_in_bytes(gt);
    int len8 = len7 + element_length_in_bytes(X);
    int len9 = len8 + element_length_in_bytes(Y);
    int len10 = len9 + element_length_in_bytes(h);
    int len11 = len10 + element_length_in_bytes(y1);
    int len12 = len11 + element_length_in_bytes(y2);
    int len13 = len12 + element_length_in_bytes(y3);
    int len14 = len13 + len_mes;

    unsigned char *buf = new unsigned char[len14];
    element_to_bytes(buf, R1);
    element_to_bytes(buf + len1, R2);
    element_to_bytes(buf + len2, R3);
    element_to_bytes(buf + len3, R4);
    element_to_bytes(buf + len4, R5);
    element_to_bytes(buf + len5, g);
    element_to_bytes(buf + len6, gt);
    element_to_bytes(buf + len7, X);
    element_to_bytes(buf + len8, Y);
    element_to_bytes(buf + len9, h);
    element_to_bytes(buf + len10, y1);
    element_to_bytes(buf + len11, y2);
    element_to_bytes(buf + len12, y3);
    // strcpy((char*)buf+len13,mes);
    memcpy((char *)buf + len13, mes, len_mes);

    unsigned char hash[20];
    sha1::calc(buf, len14, hash);
    element_from_hash(res, (void *)hash, 20);
    delete[] buf;
}

// BASE 58 convertation
string Auxiliary::Element_to_BASE_58(element_t elem)
{
    int len = element_length_in_bytes(elem);
    unsigned char *buf = new unsigned char[len];
    element_to_bytes(buf, elem);
    string ret = EncodeBase58(buf, len);
    delete[] buf;
    return ret;
}

void Auxiliary::Element_from_BASE_58(element_t elem, string elem_base58)
{
    int len = elem_base58.length();
    unsigned char *buf = new unsigned char[len];
    DecodeBase58(elem_base58, buf, len);
    element_from_bytes(elem, buf);
    delete[] buf;
}

string Auxiliary::SignatureToString(element_t c, element_t Sp, element_t Sm, element_t Sv, element_t T1, element_t T2, element_t T3, element_t T4, element_t T5, element_t T6, element_t T7)
{
    string signature;
    signature.append(Element_to_BASE_58(c) + "\n");
    signature.append(Element_to_BASE_58(Sp) + "\n");
    signature.append(Element_to_BASE_58(Sm) + "\n");
    signature.append(Element_to_BASE_58(Sv) + "\n");
    signature.append(Element_to_BASE_58(T1) + "\n");
    signature.append(Element_to_BASE_58(T2) + "\n");
    signature.append(Element_to_BASE_58(T3) + "\n");
    signature.append(Element_to_BASE_58(T4) + "\n");
    signature.append(Element_to_BASE_58(T5) + "\n");
    signature.append(Element_to_BASE_58(T6) + "\n");
    signature.append(Element_to_BASE_58(T7));
    return signature;
}

void Auxiliary::NextString(string &str, element_t elem)
{
    string tmp;
    size_t pos;
    pos = str.find("\n");
    tmp = str.substr(0, pos);
    str.erase(0, pos + 1);
    Element_from_BASE_58(elem, tmp);
}

void Auxiliary::SignatureFromString(string signature, element_t c_H, element_t Sp, element_t Sm, element_t Sv, element_t T1, element_t T2, element_t T3, element_t T4, element_t T5, element_t T6, element_t T7)
{
    NextString(signature, c_H);
    NextString(signature, Sp);
    NextString(signature, Sm);
    NextString(signature, Sv);
    NextString(signature, T1);
    NextString(signature, T2);
    NextString(signature, T3);
    NextString(signature, T4);
    NextString(signature, T5);
    NextString(signature, T6);
    NextString(signature, T7);
}

string Auxiliary::GroupPublicKeyToString(element_t g_w, element_t gt_w, element_t X_w, element_t Y_w, element_t h_w, element_t y1_w, element_t y2_w, element_t y3_w)
{
    string gpk;
    gpk.append(Element_to_BASE_58(g_w) + "\n");
    gpk.append(Element_to_BASE_58(gt_w) + "\n");
    gpk.append(Element_to_BASE_58(X_w) + "\n");
    gpk.append(Element_to_BASE_58(Y_w) + "\n");
    gpk.append(Element_to_BASE_58(h_w) + "\n");
    gpk.append(Element_to_BASE_58(y1_w) + "\n");
    gpk.append(Element_to_BASE_58(y2_w) + "\n");
    gpk.append(Element_to_BASE_58(y3_w) + "\n");
    return gpk;
}

void Auxiliary::SetPublicKey(string gpk, element_t g_r, element_t gt_r, element_t X_r, element_t Y_r, element_t h_r, element_t y1_r, element_t y2_r, element_t y3_r)
{
    NextString(gpk, g_r);
    NextString(gpk, gt_r);
    NextString(gpk, X_r);
    NextString(gpk, Y_r);
    NextString(gpk, h_r);
    NextString(gpk, y1_r);
    NextString(gpk, y2_r);
    NextString(gpk, y3_r);
}

string Auxiliary::SecretIssuingKeyToString(element_t x, element_t y)
{
    string ik;
    ik.append(Element_to_BASE_58(x) + "\n");
    ik.append(Element_to_BASE_58(y) + "\n");
    return ik;
}

void Auxiliary::SetSecretIssuingKey(string ik, element_t x, element_t y)
{
    NextString(ik, x);
    NextString(ik, y);
}

string Auxiliary::OpeningKeyToString(element_t x1, element_t x2, element_t x3, element_t x4, element_t x5)
{
    string ok;
    ok.append(Element_to_BASE_58(x1) + "\n");
    ok.append(Element_to_BASE_58(x2) + "\n");
    ok.append(Element_to_BASE_58(x3) + "\n");
    ok.append(Element_to_BASE_58(x4) + "\n");
    ok.append(Element_to_BASE_58(x5) + "\n");
    return ok;
}

void Auxiliary::SetOpeningKey(string ok, element_t x1, element_t x2, element_t x3, element_t x4, element_t x5)
{
    NextString(ok, x1);
    NextString(ok, x2);
    NextString(ok, x3);
    NextString(ok, x4);
    NextString(ok, x5);
}

string Auxiliary::SecretSigningKeyToString(element_t ki, element_t ai, element_t bi, element_t ci)
{
    string gsk;
    gsk.append(Element_to_BASE_58(ki) + "\n");
    gsk.append(Element_to_BASE_58(ai) + "\n");
    gsk.append(Element_to_BASE_58(bi) + "\n");
    gsk.append(Element_to_BASE_58(ci) + "\n");
    return gsk;
}

void Auxiliary::SetSecretSigning(string gsk, element_t ki, element_t ai, element_t bi, element_t ci)
{
    NextString(gsk, ki);
    NextString(gsk, ai);
    NextString(gsk, bi);
    NextString(gsk, ci);
}

string Auxiliary::RegisterUserToString(element_t Pi1, element_t Pi2)
{
    string db;
    db.append(Element_to_BASE_58(Pi1) + "\n");
    db.append(Element_to_BASE_58(Pi2) + "\n");
    return db;
}

vector<unsigned char> intToBytes(int paramInt)
{
    vector<unsigned char> arrayOfByte(4);
    for (int i = 0; i < 4; i++)
        arrayOfByte[3 - i] = (paramInt >> (i * 8));
    return arrayOfByte;
}