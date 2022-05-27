// The Key Generation (Setup) algorithm helps to configure and setup the environment for the CL Scheme
// ./setup < param/a.param

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
	
    // Open Secret
	element_t x1;
	element_t x2;
	element_t x3;
	element_t x4;
	element_t x5;
	
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

    /* SETUP START */

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

    // Init Open Secret Key
	element_init_Zr(x1, pairing);
	element_init_Zr(x2, pairing);
	element_init_Zr(x3, pairing);
	element_init_Zr(x4, pairing);
	element_init_Zr(x5, pairing);

    // Generate System Parameters
	element_random(g);
	element_pairing(gt, g, g);

    // Generate private keys of group manager
	element_random(x);
	element_random(y);
    
    // Compute X Y
	element_pow_zn(X, g, x);
	element_pow_zn(Y, g, y);
    
    // Generate h != 1
    do
	{
		element_random(h);
	}
	while(element_is1(h));

    //rand of secret set x1...x5
	element_random(x1);
	element_random(x2);
	element_random(x3);
	element_random(x4);
	element_random(x5);

	//compute y1
	element_pow_zn(temp_y1, gt, x1);
	element_pow_zn(temp_y2, h, x2);
	element_mul(y1, temp_y1, temp_y2);
	
    //compute y2
	element_pow_zn(temp_y1, gt, x3);
	element_pow_zn(temp_y2, h, x4);
	element_mul(y2, temp_y1, temp_y2);
	
    //compute y3
	element_pow_zn(y3, gt, x5);

	// Write Public Key on a text file
	string gpk = Auxiliary::GroupPublicKeyToString(g, gt, X, Y, h, y1, y2, y3);
	std::ofstream pkf("public_key.txt");
    pkf << gpk;
    pkf.close();

	// Write Secret Issuing Key on a text file
	string ik = Auxiliary::SecretIssuingKeyToString(x, y);
	std::ofstream ikf("secret_issuing_key.txt");
    ikf << ik;
    ikf.close();

	// Write Opening Key on a text file
	string ok = Auxiliary::OpeningKeyToString(x1, x2, x3, x4, x5);
	std::ofstream okf("opening_key.txt");
    okf << ok;
    okf.close();

    return 0;
}