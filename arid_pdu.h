#ifndef TINS_ARID_PDU_H
    #define TINS_ARID_PDU_H
    #include <tins/tins.h>
    #include <tins/pdu.h>

using namespace Tins;
/*
 * This is a dummy PDU. It behaves very similarly to Tins::RawPDU.
 */
class AridPDU : public PDU {
public:
    /* 
     * Unique protocol identifier. For user-defined PDUs, you **must**
     * use values greater or equal to PDU::USER_DEFINED_PDU;
     */
    static const PDU::PDUType pdu_flag;

    /*
     * Constructor from buffer. This constructor will be called while
     * sniffing packets, whenever a PDU of this type is found. 
     * 
     * The "data" parameter points to a buffer of length "sz". 
     */
    AridPDU(const uint8_t* data, uint32_t sz)
    : buffer_(data, data + sz) {

    }
    
    /*
     * Clones the PDU. This method is used when copying PDUs.
     */
    AridPDU* clone() const {
        return new AridPDU(*this);
    }
    
    /*
     * Retrieves the size of this PDU. 
     */
    uint32_t header_size() const {
        return buffer_.size();
    }
    
    /*
     * This method must return pdu_flag.
     */
    PDUType pdu_type() const {
        return pdu_flag;
    }
    
    /*
     * Serializes the PDU. The serialization output should be written
     * to the buffer pointed to by "data", which is of size "sz". The
     * "sz" parameter will be equal to the value returned by 
     * DummyPDU::header_size. 
     *
     * Note that before libtins 4.0, there would be an extra
     * const PDU* parameter after "sz" which would contain the parent
     * PDU. On libtins 4.0 this parameter was removed as you can get
     * the parent PDU by calling PDU::parent_pdu()
     */
    void write_serialization(uint8_t *data, uint32_t sz) {
        std::memcpy(data, buffer_.data(), sz);
    }
    
    // This is just a getter to retrieve the buffer member.
    const std::vector<uint8_t>& get_buffer() const {
        return buffer_;
    }
private:
    std::vector<uint8_t> buffer_;
};

// Let's assign some value to the pdu_flag.
const PDU::PDUType AridPDU::pdu_flag = PDU::USER_DEFINED_PDU;

#endif