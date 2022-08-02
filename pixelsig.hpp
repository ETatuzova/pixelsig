
#include <nil/crypto3/pubkey/algorithm/pubkey.hpp>
#include <nil/crypto3/pubkey/algorithm/sign.hpp>
#include <nil/crypto3/pubkey/algorithm/verify.hpp>
#include <nil/crypto3/pubkey/algorithm/aggregate.hpp>
#include <nil/crypto3/pubkey/algorithm/aggregate_verify.hpp>
#include <nil/crypto3/pubkey/algorithm/aggregate_verify_single_msg.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            /*!
             * @brief Parent class for pixel signature scheme
             * @tparam field_type -- SignatureVersion -- one of implementation classes
             * @see https://eprint.iacr.org/2019/514.pdf
             */

            template<typename SignatureVersion, typename MsgType, typename SigType, typename hash_type>
            struct pixel_parent_scheme {
                typedef SignatureVersion signature_version;

                typedef typename SignatureVersion::private_key_type private_key_type;
                typedef typename SignatureVersion::public_key_type public_key_type;
                typedef typename SignatureVersion::signature_type internal_signature_type;
                typedef typename SignatureVersion::MsgType internal_msg_type;

                static inline void setup(){}
                static inline void generate_keys(){}
                static inline void update_keys(){}
                static inline SigType sign( MsgType& msg, const private_key_type &privkey){
                    internal_msg_type hmsg = (internal_msg_type)hash<hash_type>(msg);
                    return (SigType)(SignatureVersion::sign(hmsg, privkey));   
                }
                static inline bool verify( MsgType& msg, const public_key_type &pubkey, const SigType &sig){
                    return SignatureVersion::verify(msg, pubkey, (internal_signature_type)sig);   
                }
            };

            /*!
             * @brief Basic Pixel Scheme
             * @tparam field1_type -- type of prime order field G1 that we will use
             * @tparam field2_type -- hash function we will use
             * @tparam hash_type -- class of messages
             * @see https://eprint.iacr.org/2019/514.pdf     Section 4.1
             */
            template<typename field1, typename field2>
            struct pixel_basic_scheme {
                typedef void* public_key_type;
                typedef void* private_key_type;
                typedef std::string signature_type;
                typedef std::string MsgType;

                static inline void setup(){}
                static inline void generate_keys(){}
                static inline void update_keys(){}
                static inline signature_type sign( MsgType& msg, const private_key_type &privkey){
                    return msg + ": basic pixel signature";   
                }
                static inline bool verify( MsgType& msg, const public_key_type &pubkey, const signature_type &sig){
                    return true;   
                }

                private:
                    public_key_type  public_key;
                    private_key_type private_key; 
            };

            /*!
             * @brief Encoding time Pixel Scheme
             * @tparam field_type -- type of prime order field G1 that we will use
             * @tparam hash_type -- hash function we will use
             * @tparam hash_type -- class of messages
             * @see https://eprint.iacr.org/2019/514.pdf     Section 4.1
             */
            template<typename field1, typename field2>
            struct pixel_et_scheme {
                typedef void* public_key_type;
                typedef void* private_key_type;
                typedef std::string signature_type;
                typedef std::string MsgType;

                static inline void setup(){}
                static inline void generate_keys(){}
                static inline void update_keys(){}
                static inline signature_type sign( MsgType& msg, const private_key_type &privkey){
                    return msg + ": encoding times pixel signature";   
                }
                static inline bool verify( MsgType& msg, const public_key_type &pubkey, const signature_type &sig){
                    return false;   
                }

                private:
                    public_key_type  public_key;
                    private_key_type private_key; 
            };
       }
    }
}
