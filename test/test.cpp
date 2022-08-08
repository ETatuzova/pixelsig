#define BOOST_TEST_MODULE PixelTest
#include <boost/test/unit_test.hpp>
#include <boost/test/execution_monitor.hpp>

#include <nil/crypto3/hash/md5.hpp>
#include <nil/crypto3/hash/sha1.hpp>
#include <nil/crypto3/hash/sha.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>

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

#include <vector>
#include <string>
#include <utility>
#include <random>

#include <curve_point_encode.hpp>
#include <pixel_params_type.hpp>
#include <pixel_msg_type.hpp>
#include <pixel_signature_type.hpp>
#include <pixel_key_type.hpp>
#include <pixel_signature_scheme.hpp>
#include <default_params.hpp>
#include <random_params.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::algebra;
using namespace nil::crypto3::hashes;
using namespace nil::crypto3::multiprecision;
using namespace nil::crypto3::algebra::pairing;
using namespace nil::crypto3::pixel;
 
template <typename CurveType, typename HashType, template<class> typename StaticParamsType>
void test_scheme(std::string curve_name, std::string hash_name, std::string params_name){
    BOOST_TEST_MESSAGE( "BOOST_TEST_MESSAGE curve=" << curve_name << " hash=" << hash_name << " params="<<params_name);
    using basic_scheme=pixel_parent_scheme<
        pixel_basic_scheme<
            CurveType, 
            pixel_basic_params,
            StaticParamsType,
            pixel_signature_type,
            pixel_keypair_type,
            pixel_msg_type,
            HashType
        >, 
        std::string,
        std::string
    >;
    using static_params = typename basic_scheme::static_params;

    basic_scheme::static_params::curve_name=curve_name;
    basic_scheme::setup();

    auto keypair = basic_scheme::generate_keys();
    auto keypair2 = basic_scheme::generate_keys();

    typename basic_scheme::public_key_type broken_key = keypair.pk;
    broken_key.y = keypair2.pk.y;

    std::string input = "Check me, please!";
    std::string wrong_input = "This is a message from Eve";

    auto right = basic_scheme::sign(input, keypair.sk);
    auto wrong = basic_scheme::sign(wrong_input, keypair2.sk);

//    BOOST_REQUIRE_THROW(basic_scheme::sign(input, keypair.sk), boost::execution_exception);

    BOOST_CHECK(basic_scheme::verify_public_key(keypair.pk));
    BOOST_CHECK(basic_scheme::verify_public_key(keypair2.pk));
    BOOST_CHECK(!basic_scheme::verify_public_key(broken_key));

    BOOST_CHECK(basic_scheme::verify(input, keypair.pk, 1, right));
    BOOST_CHECK(!basic_scheme::verify(input, keypair.pk, 5, right));
    BOOST_CHECK(!basic_scheme::verify(wrong_input, keypair.pk, 1, wrong));
    BOOST_CHECK(!basic_scheme::verify(input, keypair2.pk, 1, right));

    for(int i = 1; i < static_params::T+5; i++){
        keypair.sk = basic_scheme::update_keys(keypair.sk);
        if( i < static_params::T ) 
            BOOST_CHECK(keypair.sk != NULL); 
        else
            BOOST_CHECK(keypair.sk == NULL);
    }


    auto kp1 = basic_scheme::generate_keys();
    auto kp2 = basic_scheme::generate_keys();
    auto kp3 = basic_scheme::generate_keys();

    std::string mmsg = "Message for the United Signature";

    std::vector<typename basic_scheme::public_key_type> pks = {kp1.pk, kp2.pk, kp3.pk};
    auto apk = basic_scheme::aggregate_public_keys(pks);

    std::vector<typename basic_scheme::signature_type> signs = {
        basic_scheme::sign(mmsg, kp1.sk),
        basic_scheme::sign(mmsg, kp2.sk),
        basic_scheme::sign(mmsg, kp3.sk),
    };
    auto Sigma = basic_scheme::aggregate_signatures(signs);

    BOOST_CHECK(basic_scheme::verify(mmsg, apk, 1, Sigma) );
    BOOST_CHECK(!basic_scheme::verify(mmsg, kp1.pk, 1, Sigma) );
};


template <typename CurveType, typename HashType>
void test_curve_with_hash(std::string curve_name, std::string hash_name){
    test_scheme<CurveType, HashType, pixel_basic_default_params>(curve_name, hash_name, "default");
    test_scheme<CurveType, HashType, pixel_basic_random_params>(curve_name, hash_name, "random");
}


template <typename CurveType>
void test_curve(std::string curve_name){
    test_curve_with_hash<CurveType, hashes::md5>(curve_name,"md5");
    test_curve_with_hash<CurveType, hashes::sha>(curve_name, "sha");
    test_curve_with_hash<CurveType, hashes::sha1>(curve_name, "sha1");
}

void test_all(){
    test_curve<curves::bls12<381>>("bls12");
    test_curve<curves::mnt4<298>>("mnt4");
    test_curve<curves::mnt6<298>>("mnt6");
}

BOOST_AUTO_TEST_CASE( pixel_test ){
    test_all();
}