#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/curves/mnt6.hpp>
#include <nil/crypto3/algebra/curves/edwards.hpp>
#include <nil/crypto3/algebra/pairing/bls12.hpp>
#include <nil/crypto3/algebra/pairing/mnt4.hpp>
#include <nil/crypto3/algebra/pairing/mnt6.hpp>
#include <nil/crypto3/algebra/pairing/edwards.hpp>

#include <nil/crypto3/algebra/algorithms/pair.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/pubkey/algorithm/pubkey.hpp>
#include <nil/crypto3/pubkey/algorithm/sign.hpp>
#include <nil/crypto3/pubkey/algorithm/verify.hpp>
#include <nil/crypto3/pubkey/algorithm/aggregate.hpp>
#include <nil/crypto3/pubkey/algorithm/aggregate_verify.hpp>
#include <nil/crypto3/pubkey/algorithm/aggregate_verify_single_msg.hpp>
#include <nil/crypto3/pubkey/keys/private_key.hpp>
#include <nil/crypto3/pubkey/keys/public_key.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <curve_point_print.hpp>
#include <curve_point_encode.hpp>
#include <base_converter.h>
#include <boost/algorithm/string.hpp>

using namespace nil::crypto3::algebra;

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            /*!
             * @brief Parent class for pixel signature scheme
             * @tparam field_type -- SignatureVersion -- one of implementation classes
             * @see https://eprint.iacr.org/2019/514.pdf
             */

            template<typename SignatureVersion, typename MsgType, typename hash_type>
            struct pixel_parent_scheme {
                typedef SignatureVersion signature_version;

                typedef typename SignatureVersion::private_key_type private_key_type;
                typedef typename SignatureVersion::public_key_type  public_key_type;
                typedef typename SignatureVersion::keypair_type     keypair_type;
                typedef typename SignatureVersion::signature_type   internal_signature_type;
                typedef typename SignatureVersion::MsgType          internal_msg_type;

                using SigType = std::string;

                signature_version   scheme_impl;

                static inline void setup(){
                    signature_version::setup();
                }
                static inline keypair_type generate_keys(){
                    return signature_version::generate_keys();
                }
                static inline private_key_type *update_keys(private_key_type* key){
                    return signature_version::update_keys(key);
                }
                static inline SigType sign( MsgType& msg, private_key_type *privkey){
                    internal_msg_type hmsg = (internal_msg_type)hash<hash_type>(msg);
                    return (std::string)(SignatureVersion::sign(hmsg, privkey));   
                }
                static inline bool verify( MsgType& msg, const public_key_type &pubkey, int t, const SigType &sig){
                    return SignatureVersion::verify(msg, pubkey, t, (internal_signature_type)sig);   
                }
            };

            template<typename CurveType> 
            struct pixel_signature_type{
                using curve_type = CurveType;
                using g1_type = typename curve_type::template g1_type<>;
                using g2_type = typename curve_type::template g2_type<>;

                using g1_value_type = typename g1_type::value_type;
                using g2_value_type = typename g2_type::value_type;

                g1_value_type sigma1;
                g2_value_type sigma2;

                pixel_signature_type<curve_type>(g1_value_type sigma1, g2_value_type sigma2){
                    this->sigma1 = sigma1;
                    this->sigma2 = sigma2;
                }
                operator std::string(){
                    std::string  str1=stringify_curve_group_element(this->sigma1);
                    std::string  str2=stringify_curve_group_element(this->sigma2);
                    std::string  result = "[" + str1 + "," + str2 + "]";
                    return result;
                }
            };

            /*!
             * @brief Pixel private key type
             * @tparam field_type -- SignatureVersion -- one of implementation classes
             * This object can be used only once;
             * sign() function works only if used() is false. 
             * It sets used=true by use() method
             * Key should be deleted after update_keys() function call;
             * @see https://eprint.iacr.org/2019/514.pdf
             */
            template<typename CurveType>
            struct pixel_private_key_type{
                using curve_type = CurveType;
                using g1_type = typename curve_type::template g1_type<>;
                using g2_type = typename curve_type::template g2_type<>;

                using g1_value_type = typename g1_type::value_type;
                using g2_value_type = typename g2_type::value_type;

                using fr_type = typename curve_type::scalar_field_type;
                using fr_value_type = typename fr_type::value_type;

                // parts of private key
                g1_value_type hx;       // h^x --computed once
                g1_value_type hxft0r;   // (h^x)*F(t, 0)^r
                g1_value_type F1r;      // F'^r
                g2_value_type g2r;      // g2^r
                int   t;

                void use(){ this->u = true; }
                bool used(){ return this->u; }
                private:
                    bool u = false;
            };

            template<typename CurveType>
            struct pixel_public_key_type{
                using curve_type = CurveType;
                using g1_type = typename curve_type::template g1_type<>;
                using g2_type = typename curve_type::template g2_type<>;

                using g1_value_type = typename g1_type::value_type;
                using g2_value_type = typename g2_type::value_type;

                g2_value_type y;
            };

            template<typename CurveType>
            struct pixel_keypair_type{
                using private_key_type = pixel_private_key_type<CurveType>;
                using public_key_type = pixel_public_key_type<CurveType>;

                private_key_type *sk;
                public_key_type  pk;

                ~pixel_keypair_type(){
                    if(this->sk != NULL) delete[](sk);
                }
            };

            template<typename CurveType, typename StaticParams>
            struct pixel_basic_params{
                using curve_type = CurveType;
                using static_params = StaticParams;

                using g1_type = typename curve_type::template g1_type<>;
                using g1_value_type = typename g1_type::value_type;

                static void load(){
                    static_params::load();
                }

                static g1_value_type F(int t){ //function F(t, 0){
                    return random_element<typename curve_type::template g1_type<>>();
                }
            };

            /*!
             * @brief Basic Pixel Scheme
             * @tparam CurveType -- curve for bilinear group {G1,G2}->GT
             * @tparam SchemeParams -- scheme params, static member
             *          g1 -- G1 generator
             *          g2 -- G2 generator
             *          h  -- constant from G1
             *          F1 -- constant F' from F1, F'^M will be computed
             *          T  -- maximum signature rounds
             *          G1_value_type F(t) -- function F(t, 0)
             * @see https://eprint.iacr.org/2019/514.pdf     Section 4.1
             */
            template<
                typename CurveType, 
                template <class, class> typename SchemeParams, 
                template <class> typename StaticParams,
                template <class> typename SignatureType,
                template <class> typename KeyPairType
            >
            struct pixel_basic_scheme {
                using scheme_params = SchemeParams<CurveType, StaticParams<CurveType>>;
                using static_params = StaticParams<CurveType>;
                using curve_type = CurveType;

                using signature_type = SignatureType<CurveType>;
                using keypair_type = KeyPairType<CurveType>;
                using private_key_type = typename keypair_type::private_key_type;
                using public_key_type  = typename keypair_type::public_key_type;

                using g1_type = typename curve_type::template g1_type<>;
                using g2_type = typename curve_type::template g2_type<>;
                using fr_type = typename curve_type::scalar_field_type;

                using g1_value_type = typename g1_type::value_type;
                using g2_value_type = typename g2_type::value_type;
                using fr_value_type = typename fr_type::value_type;

                typedef std::string MsgType;

                static inline void setup(){ scheme_params::load(); }
                static inline keypair_type generate_keys(){
                    fr_value_type r =    random_element<fr_type>(); // fresh randomness
                    fr_value_type x =    random_element<fr_type>(); // true secret key

                    keypair_type    pair;

                    pair.sk =           new private_key_type();
                    pair.sk->hx =       x * static_params::h;
                    pair.sk->t =        1;
                    pair.sk->hxft0r =   pair.sk->hx + (r * scheme_params::F(pair.sk->t));   // (h^x)*F(t, 0)^r
                    pair.sk->F1r =      r * static_params::F1;      // F'^r
                    pair.sk->g2r =      r*static_params::g2;      // g2^r

                    pair.pk.y =           pair.sk->x * static_params::g2;

                    return pair;
                }

                static inline private_key_type * update_keys(private_key_type *old_sk){
                    if( old_sk->t == static_params::T ){
                        // keypair should be regenerated by generate_keys() function;
                        delete old_sk;
                        return NULL;
                    }
                    private_key_type *sk = new private_key_type;
                    fr_value_type r =    random_element<fr_type>(); // fresh randomness

                    sk->hx = old_sk->hx;
                    sk->t = old_sk->t + 1;
                    sk->hxFt0r =   sk->hx + (r * scheme_params::F(sk->t));   // (h^x)*F(t, 0)^r
                    sk->F1r =      r * static_params::F1;      // F'^r
                    sk->g2r =      r*static_params::g2;      // g2^r
                    
                    return sk;
                }

                static inline signature_type sign( MsgType& msg, private_key_type *sk){
                    //We can use private key only once
                    assert(!sk->used());
                    sk->use();

//                    fr_value_type M = field_element_init(msg);
                    BaseConverter conv = BaseConverter::HexToDecimalConverter();

                    std::cout << "Msg hash=" << msg << std::endl;
                    boost::to_upper(msg);
                    std::cout << "Msg hash=" << msg << std::endl;
                    std::string dec = conv.Convert(msg);
                    std::cout << "Msg decimal hash=" << dec << std::endl;
                    fr_value_type M = typename fr_value_type::integral_type(dec);

                    print_field_element(M);
                    std::cout << std::endl;
                    
                    return signature_type(sk->hxFt0r + M * sk->F1r, static_params::g2r);   
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
            template<typename CurveType>
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
                static inline bool verify( MsgType& msg, const public_key_type &pubkey, int t, const signature_type &sig){
                    return false;   
                }

                private:
                    public_key_type  public_key;
                    private_key_type private_key; 
            };
       }
    }
}
