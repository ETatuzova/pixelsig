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

#include <curve_point_print.hpp>
#include <curve_point_decode.hpp>
#include <curve_point_encode.hpp>
#include <base_converter.h>
#include <boost/algorithm/string.hpp>

#include <vector>

using namespace nil::crypto3::algebra;

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            /*!
             * @brief Parent class for pixel signature scheme
             * @tparam field_type -- SignatureVersion -- one of implementation classes
             * @see https://eprint.iacr.org/2019/514.pdf
             */

            template<typename SignatureVersion, typename MsgType, typename SignatureType>
            struct pixel_parent_scheme {
                typedef SignatureVersion signature_version;

                using signature_type = SignatureType;
                typedef typename SignatureVersion::private_key_type private_key_type;
                typedef typename SignatureVersion::public_key_type  public_key_type;
                typedef typename SignatureVersion::keypair_type     keypair_type;
                typedef typename SignatureVersion::signature_type   internal_signature_type;
                typedef typename SignatureVersion::msg_type         internal_msg_type;

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
                    internal_msg_type m(msg);
                    return (MsgType)(SignatureVersion::sign(m, privkey));   
                }
                static inline bool verify( MsgType& msg, const public_key_type &pubkey, int t, const SigType &sig){
                    internal_msg_type m(msg);
                    internal_signature_type s(sig);
                    return SignatureVersion::verify(m, pubkey, t, s);   
                }
                static inline public_key_type aggregate_public_keys(std::vector<public_key_type> &pks){
                    return SignatureVersion::aggregate_public_keys(pks);
                }
                static inline SignatureType aggregate_signatures(std::vector<SignatureType> &sigstrs){
                    std::vector<internal_signature_type> signs;
                    for( int i = 0; i < sigstrs.size(); i++){
                        signs.push_back(internal_signature_type(sigstrs[i]));
                    }
                    return (MsgType)SignatureVersion::aggregate_signatures(signs);
                }
                static inline internal_signature_type aggregate_signatures(std::vector<internal_signature_type> &signs){
                    return SignatureVersion::aggregate_signatures(signs);
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
                template <class> typename KeyPairType,
                template <class, class> typename MsgType,
                typename HashType
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
                using gt_type = typename curve_type::gt_type;
                using fr_type = typename curve_type::scalar_field_type;

                using g1_value_type = typename g1_type::value_type;
                using g2_value_type = typename g2_type::value_type;
                using gt_value_type = typename gt_type::value_type;
                using fr_value_type = typename fr_type::value_type;

                using msg_type = MsgType<CurveType, HashType>;

                static inline void setup(){ scheme_params::load(); }
                static inline keypair_type generate_keys(){
                    fr_value_type r =    random_element<fr_type>(); // fresh randomness
                    fr_value_type x =    random_element<fr_type>(); // true secret key

                    keypair_type    pair;

                    pair.sk =           new private_key_type();
                    pair.sk->hx =       x * static_params::h;
                    pair.sk->t =        1;
                    pair.sk->hxFt0r =   pair.sk->hx + (r * scheme_params::F(pair.sk->t));       // (h^x)*F(t, 0)^r
                    pair.sk->F1r =      r * static_params::F1;                                  // F'^r
                    pair.sk->g2r =      r*static_params::g2;                                    // g2^r

                    pair.pk.y =         x * static_params::g2;                                  // g2^x
                    pair.pk.hy =        pair_reduced<curve_type>(static_params::h,pair.pk.y);   //e(h,y)

                    return pair;
                }

                static inline private_key_type * update_keys(private_key_type *old_sk){
                    if( old_sk->t >= static_params::T ){
                        // keypair should be regenerated by generate_keys() function;
                        delete old_sk; // TODO :: something with memory cleaning. Keys should be dropped safely.
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

                static inline signature_type sign( msg_type &msg, private_key_type *sk){
                    //We can use private key only once
                    assert(!sk->used());
                    sk->use();

                    return signature_type(sk->hxFt0r + msg.M * sk->F1r, sk->g2r);   
                }

                static inline bool verify( msg_type& msg, const public_key_type &pk, int t, const signature_type &sig){
                    gt_value_type pairing1 = pair_reduced<curve_type>(sig.sigma1, static_params::g2);
                    gt_value_type pairing2 = pk.hy * pair_reduced<curve_type>(scheme_params::F(t) + msg.M * static_params::F1, sig.sigma2);

/*                  std::cout<<"e(sigma1,g2)"<<std::endl;
                    print_field_element(pairing1);
                    std::cout<<std::endl;
                    std::cout<<std::endl;
                    std::cout<<"e(h,y)*e(F(T)*F'^M)"<<std::endl;
                    print_field_element(pairing2);
*/
                    return pairing1 == pairing2;   
                }

                static inline public_key_type aggregate_public_keys(std::vector<public_key_type> &pks){
                    public_key_type apk;
                    apk = pks[0];

                    for(int i = 1; i < pks.size(); i++){
                        apk.y = apk.y + pks[i].y;
                        apk.hy = apk.hy * pks[i].hy;
                    }
                    return apk;
                }

                static inline signature_type aggregate_signatures(std::vector<signature_type> &signs){
                    signature_type Sigma(signs[0].sigma1, signs[0].sigma2);

                    for(int i = 1; i < signs.size(); i++){
                        Sigma.sigma1 = Sigma.sigma1 + signs[i].sigma1;
                        Sigma.sigma2 = Sigma.sigma2 + signs[i].sigma2;
                    }

                    return Sigma;
                }
            };

            /*!
             * @brief Encoding time Pixel Scheme
             * @tparam field_type -- type of prime order field G1 that we will use
             * @tparam hash_type -- hash function we will use
             * @tparam hash_type -- class of messages
             * @see https://eprint.iacr.org/2019/514.pdf     Section 4.1
             */
/*            template<typename CurveType>
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
            };*/
       }
    }
}
