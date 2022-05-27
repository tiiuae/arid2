// How to use it
// g++ !(setup|join|sign|verify).cpp ./sha1/*.cpp ./base58/*.cpp -o open -l pbc -l gmp -ltins
// sudo ./open WIFI_INTERFACE < param/a.param

#include <iostream>
#include <ctime>
#include <chrono>
#include <tins/tins.h>
#include "auxiliary.h"
#include "arid_pdu.h"
#include "colors.h"

using namespace Tins;
using namespace std::chrono;
using namespace std;

int main(int argc, char *argv[])
{
    // std::ofstream outfile;
    // outfile.open("OPEN_TEST.txt", std::ios_base::app); // append instead of overwrite

    // Pairing
    pairing_t pairing;

    /* Setup Pairing Parameters */
    char param[1024];
    size_t count = fread(param, 1, 1024, stdin);
    if (!count)
        pbc_die("input error");
    pairing_init_set_buf(pairing, param, count);

    // Public key
    element_t gt;
    element_t g;
    element_t X;
    element_t Y;
    element_t h;
    element_t y1;
    element_t y2;
    element_t y3;

    // Open Secret
    element_t x1;
    element_t x2;
    element_t x3;
    element_t x4;
    element_t x5;

    // Init Public Key gpk
    element_init_G1(g, pairing);
    element_init_GT(gt, pairing);
    element_init_G1(X, pairing);
    element_init_G1(Y, pairing);
    element_init_GT(h, pairing);
    element_init_GT(y1, pairing);
    element_init_GT(y2, pairing);
    element_init_GT(y3, pairing);

    // Init Open Secret Key
    element_init_Zr(x1, pairing);
    element_init_Zr(x2, pairing);
    element_init_Zr(x3, pairing);
    element_init_Zr(x4, pairing);
    element_init_Zr(x5, pairing);

    // Read Public Key from file
    std::ifstream inFile;
    inFile.open("public_key.txt"); // open the public key
    std::stringstream strStream;
    strStream << inFile.rdbuf();  // read the file
    inFile.close();               // close the file
    string gpk = strStream.str(); // str holds the content of the file
    Auxiliary::SetPublicKey(gpk, g, gt, X, Y, h, y1, y2, y3);

    // Read Opening Key
    strStream.str(std::string());   // Clean the Stream
    inFile.open("opening_key.txt"); // open the secret issuing key
    strStream << inFile.rdbuf();    // read the file
    inFile.close();                 // close the file
    string ok = strStream.str();    // str holds the content of the file
    Auxiliary::SetOpeningKey(ok, x1, x2, x3, x4, x5);

    // Networking Part
    Allocators::register_allocator<Dot1Q, AridPDU>(0xa21d);
    SnifferConfiguration config;            // Comment the config part if you want to test in local
    config.set_direction(PCAP_D_IN);
    config.set_immediate_mode(true);
    //config.set_rfmon(true);               //SIOCGIWPRIV: Argument list too long
    Sniffer sniffer(argv[1], config);

    for (;;)
    {
        try
        {
            Packet pkt(sniffer.next_packet());
            const AridPDU &arid = pkt.pdu()->rfind_pdu<AridPDU>();
            if (arid.pdu_type() == PDU::USER_DEFINED_PDU)
            {
                vector<uint8_t> buffer = arid.get_buffer();

                // Message
                const char recv_payload[41] = {
                    buffer[0], buffer[1], buffer[2], buffer[3],     // STATIC ID
                    buffer[4], buffer[5], buffer[6], buffer[7],     // Drone Latitude
                    buffer[8], buffer[9], buffer[10], buffer[11],   // Drone Longitude
                    buffer[12], buffer[13], buffer[14], buffer[15], // Drone Altitude
                    buffer[16], buffer[17], buffer[18], buffer[19], // Drone Speed
                    buffer[20], buffer[21], buffer[22], buffer[23], // Drone COG
                    buffer[24], buffer[25], buffer[26], buffer[27], // UAS Latitude
                    buffer[28], buffer[29], buffer[30], buffer[31], // UAS Longitude
                    buffer[32], buffer[33], buffer[34], buffer[35], // UAS Altitude
                    buffer[36], buffer[37], buffer[38], buffer[39], // Timestamp
                    buffer[40]                                      // Emergency Code
                };

                uint16_t len_sign = buffer[41] * 256 + buffer[42];                                     // Signature Len
                string sign(buffer.begin() + (sizeof(recv_payload) + sizeof(len_sign)), buffer.end()); // Signature

                // compare variables
                bool cmp_value_1 = 0;
                bool cmp_value_2 = 0;

                // elements
                element_t T1r, T2r, T3r, T4r;
                element_t T5r, T6r, T7r;
                element_t c_Hr;
                element_t Hr;
                element_t Spr;
                element_t Smr;
                element_t Svr;

                // init
                element_init_GT(T1r, pairing);
                element_init_GT(T2r, pairing);
                element_init_GT(T3r, pairing);
                element_init_GT(T4r, pairing);
                element_init_G1(T5r, pairing);
                element_init_G1(T6r, pairing);
                element_init_G1(T7r, pairing);
                element_init_Zr(Spr, pairing);
                element_init_Zr(Smr, pairing);
                element_init_Zr(Svr, pairing);
                element_init_Zr(Hr, pairing);
                element_init_Zr(c_Hr, pairing);

                Auxiliary::SignatureFromString(sign, c_Hr, Spr, Smr, Svr, T1r, T2r, T3r, T4r, T5r, T6r, T7r);
                Auxiliary::Hash_T1_T2_T3(Hr, T1r, T2r, T3r);

                // compute R1'
                element_t tmp_1;
                element_t tmp_2;
                element_t tmp_3;
                element_t R1_;
                element_init_GT(R1_, pairing);
                element_init_GT(tmp_1, pairing);
                element_init_GT(tmp_2, pairing);
                element_init_GT(tmp_3, pairing);

                element_pairing(tmp_1, g, T7r);     // e(g, T7)
                element_pow_zn(tmp_2, tmp_1, Spr);  // e(g, T7)^rp
                element_pairing(tmp_1, X, T6r);     // e(X, T6)
                element_pow_zn(tmp_3, tmp_1, Smr);  // e(X, T6)^rm
                element_div(R1_, tmp_2, tmp_3);     // e(g, T7)^rp / e(X, T6)^rm
                element_pairing(tmp_3, X, T5r);     // e(X, T5)
                element_pow_zn(tmp_3, tmp_3, c_Hr); // e(X, T5)^H
                element_div(R1_, R1_, tmp_3);       // e(g, T7)^rp / e(X, T6)^rm / e(X, T5)^H ==> e(g, T7)^rp / [e(X, T6)^rm * e(X, T5)^H]

                // compute R2'
                element_t R2_;
                element_init_GT(R2_, pairing);

                element_pow_zn(R2_, gt, Svr);     // R2 = gt^v
                element_pow_zn(tmp_1, T1r, c_Hr); // T1^H
                element_div(R2_, R2_, tmp_1);     // R2 = gt^v/T1^H

                // compute R3'
                element_t R3_;
                element_init_GT(R3_, pairing);

                element_pow_zn(tmp_1, h, Svr);    // h^v
                element_pow_zn(tmp_2, T2r, c_Hr); // T2^H
                element_sub(R3_, tmp_1, tmp_2);   // R3 = h^v- T2^H

                // compute R4'
                element_t R4_;
                element_init_GT(R4_, pairing);

                element_pow_zn(tmp_1, y1, Svr);   // y1^v
                element_pow_zn(tmp_2, gt, Smr);   // gt^m
                element_mul(tmp_3, tmp_1, tmp_2); // y^v * gt^m
                element_pow_zn(tmp_1, T3r, c_Hr); // T3^H
                element_sub(R4_, tmp_3, tmp_1);   // R4 = (y1^v * gt^m) - T3^H

                // compute R5'
                element_t R5_, tmp_pow, tmp_div;
                element_init_GT(R5_, pairing);
                element_init_Zr(tmp_pow, pairing);
                element_init_GT(tmp_div, pairing);

                element_pow_zn(R5_, y2, Svr);          // R5 = y2^v
                element_pow_zn(tmp_div, y3, Hr);       // y3^H
                element_pow_zn(tmp_div, tmp_div, Svr); // y3^(H*v)
                element_mul(R5_, R5_, tmp_div);        // R5 = y2^v * y3^(H*v)
                element_pow_zn(tmp_div, T4r, c_Hr);    // T4^H
                element_div(R5_, R5_, tmp_div);        //  [y2^v * y3^(H*v)]/T4^H

                // check c_H == c_H'
                element_t check_c_H;
                element_init_Zr(check_c_H, pairing);
                Auxiliary::Hash_C(check_c_H, R1_, R2_, R3_, R4_, R5_, g, gt, X, Y, h, y1, y2, y3, (char *)recv_payload, sizeof(recv_payload));

                // check e(T 5 , Y ) == e(g, T 6 )
                element_t check_1;
                element_init_GT(check_1, pairing);

                element_t check_2;
                element_init_GT(check_2, pairing);

                element_pairing(check_1, T5r, Y);
                element_pairing(check_2, g, T6r);

                // cmp_value_1
                cmp_value_1 = element_cmp(check_c_H, c_Hr); // 0==success

                // cmp_value_2
                cmp_value_2 = element_cmp(check_1, check_2); // 0==success

                if (cmp_value_1 == 0 && cmp_value_2 == 0)
                    cout << GREEN << "Valid Signature" << RESET << endl;
                else
                    cout << RED << "Signature Not Valid" << RESET << endl;

                // Only if the signature is valid
                if (cmp_value_1 == 0 && cmp_value_2 == 0)
                {
                    // compare variable
                    bool cmp_var = 0;
                    // elements
                    element_t Pi2; // Read from Database
                    element_t T1o, T2o, T3o, T4o;
                    element_t T5o, T6o, T7o;
                    element_t Ho;
                    element_t Spo;
                    element_t Smo;
                    element_t Svo;
                    element_t c_Ho;
                    element_t tmp_pow;
                    element_t check_T4;
                    element_t tmp_T2;
                    element_init_GT(T1o, pairing);
                    element_init_GT(T2o, pairing);
                    element_init_GT(T3o, pairing);
                    element_init_GT(T4o, pairing);
                    element_init_G1(T5o, pairing);
                    element_init_G1(T6o, pairing);
                    element_init_G1(T7o, pairing);
                    element_init_Zr(Ho, pairing);
                    element_init_Zr(Spo, pairing);
                    element_init_Zr(Smo, pairing);
                    element_init_Zr(Svo, pairing);
                    element_init_Zr(c_Ho, pairing);
                    element_init_Zr(tmp_pow, pairing);
                    element_init_GT(check_T4, pairing);
                    element_init_GT(tmp_T2, pairing);

                    // read sign
                    Auxiliary::SignatureFromString(sign, c_Ho, Spo, Smo, Svo, T1o, T2o, T3o, T4o, T5o, T6o, T7o);

                    // add verify sign
                    Auxiliary::Hash_T1_T2_T3(Ho, T1o, T2o, T3o);

                    // T4 check
                    element_mul(tmp_pow, x5, Ho);            // x5*H
                    element_add(tmp_pow, tmp_pow, x3);       // x5*H + x3
                    element_pow_zn(check_T4, T1o, tmp_pow);  // T4 = T1^(x5*H + x3)
                    element_pow_zn(tmp_T2, T2o, x4);         // T2^x4
                    element_mul(check_T4, check_T4, tmp_T2); // T4 = T1^(x5*H + x3)*T2^x4
                    cmp_var = element_cmp(check_T4, T4o);    // 0==ok --> SUCCESS!

                    // compute Pi2
                    element_t check_Pi2;
                    element_init_GT(check_Pi2, pairing);

                    element_pow_zn(tmp_T2, T1o, x1);        // T1^x1
                    element_pow_zn(check_Pi2, T2o, x2);     // T2^x2
                    element_mul(tmp_T2, tmp_T2, check_Pi2); // T1^x1*T2^x2
                    element_div(check_Pi2, T3o, tmp_T2);    // Pi2 = T3/T1^x1*T2^x2

                    // auto end = high_resolution_clock::now();
                    // duration<double> diff = end - start; // this is in ticks
                    // outfile << diff.count() << "\n";

                    string check_Pi2_str = Auxiliary::Element_to_BASE_58(check_Pi2);
                    ifstream db;
                    db.open("database.txt");
                    string line;
                    bool cmp_Pi2 = -1;
                    for (unsigned int curLine = 1; getline(db, line); curLine++)
                    {
                        if (line.find(check_Pi2_str) != string::npos)
                        {
                            // cout << "found: " << check_Pi2_str << "line: " << curLine/2 << endl;
                            cout << MAGENTA << "[USER]: " << curLine / 2 << RESET << endl;
                            cmp_Pi2 = 0;
                        }
                    }

                    // bool cmp_Pi2 = element_cmp(Pi2, check_Pi2);//0==success
                    if (cmp_Pi2 == 0)
                    {
                        cout << YELLOW << "Opening Procedure Correct!" << RESET << endl;
                    }
                    else
                    {
                        cout << RED << "Opening Procedure Not Valid" << RESET << endl;
                    }
                }
            }
        }
        catch (malformed_packet &)
        {
        }
        catch (pdu_not_found &)
        {
        }
    }

    // Message
    // string mes;

    // GROUP ID Drone
    // const char bytes[] = {0x43, 0x41, 0x46, 0x45}; // STATIC ID
    // string grp_id(bytes, sizeof(bytes));

    // mes.append(grp_id);

    // auto start = high_resolution_clock::now();
}