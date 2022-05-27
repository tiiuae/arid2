// How to use it
// g++ -std=c++17 -L/usr/lib -I/usr/local/include/mavsdk !(setup|join|verify|open).cpp ./sha1/*.cpp ./base58/*.cpp -o sign -l pbc -l gmp -ltins -lmavsdk -lmavsdk_telemetry
// sudo ./sign WIFI_INTERFACE < param/a.param

#include <ctime>
#include <chrono>
#include <mavsdk/mavsdk.h>
#include <mavsdk/plugins/telemetry/telemetry.h>
#include <cstdint>
#include <future>
#include <thread>
#include <fcntl.h>

#include "auxiliary.h"
#include "arid_pdu.h"

using namespace std::chrono;
using namespace std;
using namespace mavsdk;
using namespace Tins;

std::shared_ptr<System> get_system(Mavsdk &mavsdk)
{
    std::cout << "Waiting to discover system...\n";
    auto prom = std::promise<std::shared_ptr<System>>{};
    auto fut = prom.get_future();

    // We wait for new systems to be discovered, once we find one that has an
    // autopilot, we decide to use it.
    mavsdk.subscribe_on_new_system([&mavsdk, &prom]()
                                   {
        auto system = mavsdk.systems().back();

        if (system->has_autopilot()) {
            std::cout << "Discovered autopilot\n";

            // Unsubscribe again as we only want to find one system.
            //mavsdk.subscribe_on_new_system(nullptr);
            prom.set_value(system);
        } });

    // We usually receive heartbeats at 1Hz, therefore we should find a
    // system after around 3 seconds max, surely.
    if (fut.wait_for(seconds(3)) == std::future_status::timeout)
    {
        std::cerr << "No autopilot found.\n";
        return {};
    }

    // Get discovered system now.
    return fut.get();
}

static bool _received_position = false;
void print_position(Telemetry::RawGps position)
{
    std::cout << "lat: " << position.latitude_deg << " deg, "
              << "lon: " << position.longitude_deg << " deg, "
              << "alt: " << position.absolute_altitude_m << " m, "
              << "speed: " << position.velocity_m_s << " m/s" << '\n';
    _received_position = true;
}

int main(int argc, char *argv[])
{
    // Initialize MAVSDK
    Mavsdk mavsdk;
    ConnectionResult connection_result = mavsdk.add_any_connection("udp://:14540");

    if (connection_result != ConnectionResult::Success)
    {
        std::cerr << "Connection failed: " << connection_result << '\n';
        return 1;
    }

    auto system = get_system(mavsdk);
    if (!system)
    {
        return 1;
    }

    auto telemetry = std::make_shared<Telemetry>(system);

    int lat, lon, alt, speed, cog;

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

    // Secret Signing Key
    element_t ai;
    element_t bi;
    element_t ci;
    element_t ki;
    element_init_G1(ai, pairing);
    element_init_G1(bi, pairing);
    element_init_G1(ci, pairing);
    element_init_Zr(ki, pairing);

    // Random Entropy
    char *src_rnd = (char *)"/dev/random";
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

    // Read Public Key from file
    std::ifstream inFile;
    inFile.open("public_key.txt"); // open the public key
    std::stringstream strStream;
    strStream << inFile.rdbuf();  // read the file
    inFile.close();               // close the file
    string gpk = strStream.str(); // str holds the content of the file
    Auxiliary::SetPublicKey(gpk, g, gt, X, Y, h, y1, y2, y3);

    // Read Membership Certificate and Secret Signing Key (gpk, ki, ai, bi, ci)
    strStream.str(std::string());            // Clean the Stream
    inFile.open("secret_signing_key_i.txt"); // open the secret signing key
    strStream << inFile.rdbuf();             // read the file
    inFile.close();                          // close the file
    string gsk_i = strStream.str();          // str holds the content of the file
    Auxiliary::SetSecretSigning(gsk_i, ki, ai, bi, ci);

    element_t r1, r2; // r r' (in the singature generation)
    element_t T1, T2, T3, T4;
    element_t T5, T6, T7;
    element_t member_Pi2;
    element_t u;
    element_t H;

    // Initialize Elements for 1. and 2. Signature Generation
    element_init_GT(member_Pi2, pairing);
    element_init_Zr(r1, pairing);
    element_init_Zr(r2, pairing);
    element_init_GT(T1, pairing);
    element_init_GT(T2, pairing);
    element_init_GT(T3, pairing);
    element_init_GT(T4, pairing);
    element_init_G1(T5, pairing);
    element_init_G1(T6, pairing);
    element_init_G1(T7, pairing);
    element_init_Zr(u, pairing);
    element_init_Zr(H, pairing);

    // auto start = high_resolution_clock::now();
    for (;;)
    {
        // Setting
        element_random(r1);
        element_random(r2);

        // compute T5 T6 T7
        element_pow_zn(T5, ai, r2); // T5 = ai^r2
        element_pow_zn(T6, bi, r2); // T6 = bi^r2
        element_pow_zn(T7, ci, r1);
        element_pow_zn(T7, T7, r2); // T7 = ci^(r2r1)

        // compute Pi2
        element_pow_zn(member_Pi2, gt, ki); // Pi2 = gt^ki = e(Pi,g)

        // Encrypt Pi2 under the group public Key
        element_random(u);

        // compute T1 T2 T3
        element_pow_zn(T1, gt, u); // T1 = gt^u
        element_pow_zn(T2, h, u);  // T2 = h^u
        element_pow_zn(T3, y1, u);
        element_mul(T3, T3, member_Pi2); // T3 = y1^u * Pi2

        // H(T1||T2||T3)
        Auxiliary::Hash_T1_T2_T3(H, T1, T2, T3);

        // compute T4
        element_t temp_GT;
        element_init_GT(temp_GT, pairing);

        element_pow_zn(temp_GT, y2, u);
        element_pow_zn(T4, y3, H);
        element_pow_zn(T4, T4, u);
        element_mul(T4, T4, temp_GT); // T4 = y2^u * y3^(u*H(T1||T2||T3))

        // Compute S as a signature of knowledge

        // Set rp rm rv
        element_t rp, rm, rv;
        element_t tmp1_s, tmp2_s;
        element_init_Zr(rp, pairing); // ro
        element_init_Zr(rm, pairing); // mu
        element_init_Zr(rv, pairing); // ni
        element_init_GT(tmp1_s, pairing);
        element_init_GT(tmp2_s, pairing);

        // Set ro, mu, ni
        element_random(rp);
        element_random(rm);
        element_random(rv);

        element_t R1;
        element_t R2;
        element_t R3;
        element_t R4;
        element_t R5;

        element_init_GT(R1, pairing);
        element_init_GT(R2, pairing);
        element_init_GT(R3, pairing);
        element_init_GT(R4, pairing);
        element_init_GT(R5, pairing);

        // compute R1
        element_pairing(tmp1_s, g, T7);     // e(g, T7)
        element_pow_zn(tmp1_s, tmp1_s, rp); // e(g, T7)^rp
        element_pairing(tmp2_s, X, T6);     // e(X, T6)
        element_pow_zn(tmp2_s, tmp2_s, rm); // e(X, T6)^rm
        element_div(R1, tmp1_s, tmp2_s);    // R1 = e(g, T7)^rp / e(X, T6)^rm

        // compute R2
        element_pow_zn(R2, gt, rv); // R2 = gt^rv

        // compute R3
        element_pow_zn(R3, h, rv); // R3 = h^rv

        // compute R4
        element_pow_zn(tmp1_s, y1, rv);
        element_pow_zn(tmp2_s, gt, rm);
        element_mul(R4, tmp1_s, tmp2_s); // R4 = y1^rv * gt^rm

        // compute R5
        element_pow_zn(tmp2_s, y3, rv);
        element_pow_zn(tmp2_s, tmp2_s, H);
        element_pow_zn(R5, y2, rv);
        element_mul(R5, R5, tmp2_s); // R5 = y3^(rv*H(T1||T2||T3))

        // Get GPS and Drone Parameters
        while (_received_position == false)
        {
            telemetry->subscribe_raw_gps([&](Telemetry::RawGps position)
                                         { 
            lat     = static_cast<int>(position.latitude_deg * 1e6);
            lon     = static_cast<int>(position.longitude_deg * 1e6);
            alt     = static_cast<int>(position.absolute_altitude_m * 1e6);
            speed   = static_cast<int>(position.velocity_m_s * 1e6);
            cog     = static_cast<int>(position.cog_deg * 1e6);
            print_position(position); });
        }

        // Message
        string mes;
        int drone_id = 3405691582; // Static ID

        // Timestamp
        time_t result = std::time(nullptr);
        int ts = result; // Put the timestamp in 4 bytes

        // ...
        const unsigned char id_bytes[4] = {(drone_id >> 24), (drone_id >> 16), (drone_id >> 8), (drone_id >> 0)}; // STATIC ID
        const char latb[4] = {(lat >> 24), (lat >> 16), (lat >> 8), (lat >> 0)};                                  // Drone Latitude
        const char lonb[4] = {(lon >> 24), (lon >> 16), (lon >> 8), (lon >> 0)};                                  // Drone Longitude
        const char altb[4] = {(alt >> 24), (alt >> 16), (alt >> 8), (alt >> 0)};                                  // Drone Altitude
        const char speedb[4] = {(speed >> 24), (speed >> 24), (speed >> 24), (speed >> 24)};                      // Drone Speed
        const char cogb[4] = {(cog >> 24), (cog >> 24), (cog >> 24), (cog >> 24)};                                // Course Over Ground
        const char latub[4] = {(lat >> 24), (lat >> 16), (lat >> 8), (lat >> 0)};                                 // UAS Latitude
        const char lonub[4] = {(lon >> 24), (lon >> 16), (lon >> 8), (lon >> 0)};                                 // UAS Longitude
        const char altub[4] = {(alt >> 24), (alt >> 16), (alt >> 8), (alt >> 0)};                                 // UAS Altitude
        const char tsb[4] = {(ts >> 24), (ts >> 16), (ts >> 8), (ts >> 0)};                                       // Timestamp
        const char es_bytes[1] = {0x01};                                                                          // Emergency Code

        char message[41] = {
            (drone_id >> 24), (drone_id >> 16), (drone_id >> 8), (drone_id >> 0), // Static ID
            (lat >> 24), (lat >> 16), (lat >> 8), (lat >> 0),                     // Drone Latitude
            (lon >> 24), (lon >> 16), (lon >> 8), (lon >> 0),                     // Drone Longitude
            (alt >> 24), (alt >> 16), (alt >> 8), (alt >> 0),                     // Drone Altitude
            (speed >> 24), (speed >> 24), (speed >> 24), (speed >> 24),           // Speed
            (cog >> 24), (cog >> 24), (cog >> 24), (cog >> 24),                   // Course Over Ground (COG)
            (lat >> 24), (lat >> 16), (lat >> 8), (lat >> 0),                     // UAS Latitude
            (lon >> 24), (lon >> 16), (lon >> 8), (lon >> 0),                     // UAS Longitude
            (alt >> 24), (alt >> 16), (alt >> 8), (alt >> 0),                     // UAS Altitude
            (ts >> 24), (ts >> 16), (ts >> 8), (ts >> 0),                         // Timestamp
            0x01                                                                  // Emergency Code
        };

        mes.append(reinterpret_cast<const char *>(id_bytes), sizeof(id_bytes) / sizeof(id_bytes[0]));
        mes.append(reinterpret_cast<const char *>(latb), sizeof(latb) / sizeof(latb[0]));
        mes.append(reinterpret_cast<const char *>(lonb), sizeof(lonb) / sizeof(lonb[0]));
        mes.append(reinterpret_cast<const char *>(altb), sizeof(altb) / sizeof(altb[0]));
        mes.append(reinterpret_cast<const char *>(speedb), sizeof(speedb) / sizeof(speedb[0]));
        mes.append(reinterpret_cast<const char *>(cogb), sizeof(cogb) / sizeof(cogb[0]));
        mes.append(reinterpret_cast<const char *>(latub), sizeof(latub) / sizeof(latub[0]));
        mes.append(reinterpret_cast<const char *>(lonub), sizeof(lonub) / sizeof(lonub[0]));
        mes.append(reinterpret_cast<const char *>(altub), sizeof(altub) / sizeof(altub[0]));
        mes.append(reinterpret_cast<const char *>(&tsb), sizeof(tsb) / sizeof(tsb[0]));
        mes.append(reinterpret_cast<const char *>(es_bytes), sizeof(es_bytes) / sizeof(es_bytes[0]));

        // Now, we will add the Signature LEN and then the Signature

        // compute c_H
        element_t c_H;
        element_init_Zr(c_H, pairing);
        // Auxiliary::Hash_C(c_H,R1,R2,R3,R4,R5,g,gt,X,Y,h,y1,y2,y3, (char*)mes.data(), mes.length());
        Auxiliary::Hash_C(c_H, R1, R2, R3, R4, R5, g, gt, X, Y, h, y1, y2, y3, (char *)message, sizeof(message));

        element_t Sp, Sm, Sv;
        element_init_Zr(Sp, pairing);
        element_init_Zr(Sm, pairing);
        element_init_Zr(Sv, pairing);

        // compute Sp
        element_div(Sp, c_H, r1); // Sp = c_H/r1
        element_add(Sp, Sp, rp);  // Sp = c_H/r1 + rp

        // compute Sm
        element_mul(Sm, c_H, ki); // Sm = c_H*ki
        element_add(Sm, Sm, rm);  // Sm = c_H*ki + rm

        // compute Sv
        element_mul(Sv, c_H, u); // Sv = c_H*u
        element_add(Sv, Sv, rv); // Sv = Sv + rv

        // something to measure
        // auto end = high_resolution_clock::now();
        // duration<double> diff = end - start; // this is in ticks
        // milliseconds d = duration_cast<milliseconds>(diff); // ticks to time

        // std::cout << diff.count() << "s\n";
        // std::cout << d.count() << "ms\n";

        // Write Signature on a text file
        // Convert signature to hex string
        string sign = Auxiliary::SignatureToString(c_H, Sp, Sm, Sv, T1, T2, T3, T4, T5, T6, T7);
        // std::cout << "Signature LEN (B58): " << sign_len << std::endl;

        // std::ofstream signf("signature.txt"); // just to check
        // signf << sign;
        // signf.close();

        int16_t sign_len = sign.length();
        sign_len = ntohs(sign_len);
        mes.append(reinterpret_cast<char *>(&sign_len), sizeof sign_len); // Signature Len

        // ARID^2 Protocol - Networking Part
        Allocators::register_allocator<Dot1Q, AridPDU>(0xa21d);
        vector<uint8_t> payload(mes.begin(), mes.end());
        payload.insert(payload.end(), sign.begin(), sign.end());

        Dot11Data data = Dot11Data() / SNAP() / AridPDU(payload.data(), payload.size());

        data.addr1(Dot11::BROADCAST);
        data.addr2("00:c0:ca:af:60:ef");
        data.addr3(data.addr2());

        RadioTap radio = RadioTap() / data;
        radio.antenna(0);
        radio.db_signal(20);
        radio.dbm_signal(20);
        Tins::RadioTap::FrameFlags FCS;
        radio.flags(FCS);

        PacketSender sender(argv[1]);
        // for (int32_t i = 0; i < mes.size(); ++i)
        // {
        //     printf("%hhx", mes[i]);
        // }
        //cout << std::endl;
        sender.send(radio, argv[1]);
        //sleep(1); // According to the RemoteID specifications
        _received_position == false;
    }

    return 0;
}