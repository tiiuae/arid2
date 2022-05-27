// The Join protocol is executed between the issuer with input (gpk, x, y) and a prospecitve memember i with input gpk (Master Public Key).

#include <ctime>
#include <chrono>
#include "auxiliary.h"

using namespace std::chrono;
using namespace std;

int main()
{
    // Pairing
	pairing_t pairing;
	
    // Public key
    element_t gt;
	element_t g;
	element_t X;
	element_t Y;
	element_t h;
	element_t y1;
	element_t y2;
	element_t y3;

    // Issuer Secret
	element_t x;
	element_t y;

    /* Setup Pairing Parameters */
    char param[1024];
    size_t count = fread(param, 1, 1024, stdin);
    if (!count) pbc_die("input error");
    pairing_init_set_buf(pairing, param, count);

    // Set tmp variables
	element_t temp_y1;
	element_t temp_y2;
	element_init_GT(temp_y1, pairing);
	element_init_GT(temp_y2, pairing);

    // Random Entropy
    char* src_rnd = (char*)"/dev/random";
    pbc_random_set_file(src_rnd);

    // Init Public Key gpk
    element_init_G1(g, pairing);
    element_init_GT(gt, pairing);
    element_init_G1(X, pairing);
    element_init_G1(Y, pairing);
    element_init_GT(h, pairing);
    element_init_GT(y1, pairing);
    element_init_GT(y2, pairing);
    element_init_GT(y3, pairing);

    // Init Issuer Secret
    element_init_Zr(x, pairing);
	element_init_Zr(y, pairing);

    // Read Public Key from file
    std::ifstream inFile;
    inFile.open("public_key.txt"); //open the public key
    std::stringstream strStream;
    strStream << inFile.rdbuf(); //read the file
    inFile.close(); //close the file
    string gpk = strStream.str(); //str holds the content of the file
    Auxiliary::SetPublicKey(gpk, g, gt, X, Y, h, y1, y2, y3);

    // Read Secret Issuing Key (Issuer)
    strStream.str(std::string()); // Clean the Stream
    inFile.open("secret_issuing_key.txt"); //open the secret issuing key
    strStream << inFile.rdbuf(); //read the file
    inFile.close(); //close the file
    string ik = strStream.str(); //str holds the content of the file
    Auxiliary::SetSecretIssuingKey(ik, x, y);

    // Join Phase Start
    element_t ki;
    element_t Pi1;
    element_t R;
    element_t rk;
    element_t Sk;
    element_t c_Hsok;
    string hash;

    // Member i generate ki and Pi1 = g^ki
    element_init_Zr(ki, pairing);
	element_random(ki);

    //compute Pi1
    element_init_G1(Pi1, pairing);
    element_pow_zn(Pi1, g, ki);

    //compute SoK
    element_init_Zr(rk, pairing);
    element_init_G1(R, pairing);
    
    element_random(rk);     // Chose rk in Zq
    element_pow_zn(R,g,rk); // R = g^rk

    
    hash = Auxiliary::Hash_g_R(g, R);

    element_init_Zr(Sk, pairing);
    element_init_Zr(c_Hsok, pairing);
    
    element_from_hash(c_Hsok,(void*)hash.c_str(),hash.length()); //Generate an element 'e' deterministically from the 'len' bytes stored in the buffer 'data'.
    element_mul(Sk, c_Hsok, ki); // Sk = c_Hsok*ki
    element_add(Sk, Sk, rk);    // Sk = c_Hsok*ki + rk

    // Member sends the request as (hash, Sk, Pi1) to the Issuer
    // check Pi1 is point of curve
	if(element_item_count(Pi1)!=2)
	{
    	return 1;//failure
	}

    element_t tmp1, tmp2, tmpR;
    string hash_check;
    element_init_G1(tmp1, pairing);
	element_init_G1(tmp2, pairing);
    element_init_G1(tmpR, pairing);
    
    element_pow_zn(tmp1, g, Sk);
	element_pow_zn(tmp2, Pi1, c_Hsok);
	element_div(tmpR, tmp1, tmp2);

    hash_check = Auxiliary::Hash_g_R(g, tmpR);
	if(hash.compare(hash_check))
	{
    	cout << "Failure"<< endl;
    	return 1;//failure
	}

    //Issuer generate r
	element_t issuer_r;
	element_init_Zr(issuer_r, pairing);
	element_random(issuer_r);

    //Create ai, bi, ci
	element_t ai;
	element_t bi;
	element_t ci;
	element_t temp_ci1;
	element_t temp_ci2;
	
    //Initialize the parameters
	element_init_G1(ai, pairing);
	element_init_G1(bi, pairing);
	element_init_G1(ci, pairing);
	element_init_G1(temp_ci1, pairing);
	element_init_G1(temp_ci2, pairing);

    //Compute ai, bi, ci
	element_pow_zn(ai,g,issuer_r); //ai = g^r
	element_pow_zn(bi,ai,y); //bi = ai^y
    element_pow_zn(temp_ci1,ai,x);
	element_pow_zn(temp_ci2,Pi1,issuer_r);
	element_pow_zn(temp_ci2,temp_ci2,x);
	element_pow_zn(temp_ci2,temp_ci2,y);
	element_mul(ci,temp_ci1,temp_ci2); //ci = ai^x * Pi1^(rxy)
    
    // Issuer Compute Pi2
    element_t Pi2;
    element_init_GT(Pi2, pairing);
	element_pairing(Pi2, Pi1, g); // Pi2 = e(Pi1, g)

    // Write Secret Signing Key on a text file for the user i
	string gsk = Auxiliary::SecretSigningKeyToString(ki, ai, bi, ci);
	std::ofstream gskf("secret_signing_key_i.txt");
    gskf << gsk;
    gskf.close();

    // The issuer should register the user in a List
    // reg[i] = (Pi1, Pi2)
    string useri = Auxiliary::RegisterUserToString(Pi1, Pi2);
	//std::ofstream usersf("database.txt");
    std::ofstream usersf;
    usersf.open("database.txt", std::ios_base::app); // append instead of overwrite
    usersf << useri;
    usersf.close();

    return 0;
}