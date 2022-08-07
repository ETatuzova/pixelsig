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

#include <pixel_signature_scheme.hpp>
#include <default_params.hpp>
//#include <random_params.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::algebra;
using namespace nil::crypto3::pubkey;
using namespace nil::crypto3::hashes;
using namespace nil::crypto3::multiprecision;
using namespace nil::crypto3::algebra::pairing;

typedef std::string signature_type;
typedef pixel_parent_scheme<
    pixel_basic_scheme<
        curves::bls12<381>, 
        pixel_basic_params,
        pixel_basic_default_params,
        pixel_signature_type,
        pixel_keypair_type,
        pixel_msg_type,
        hashes::md5
    >, 
    std::string,
    std::string
> BasicBlsScheme;

int main(int argc, char *argv[]) {
    pixel_basic_default_params<curves::bls12<381>>::curve_name="bls12";
    BasicBlsScheme::setup();
    BasicBlsScheme::keypair_type keypair = BasicBlsScheme::generate_keys();
    std::string input = "It is Sunday";

    std::string wrong = BasicBlsScheme::sign(input, keypair.sk);
//    BasicBlsScheme::sign(input, keypair.sk); // This should call assertion;
    keypair.sk = BasicBlsScheme::update_keys(keypair.sk);
    std::string right = BasicBlsScheme::sign(input, keypair.sk);

    if( BasicBlsScheme::verify(input, keypair.pk, 2, right) ){
        std::cout << "Signature is right" << std::endl;
    } else {
        std::cout << "Signature is wrong" << std::endl;
    };

    if( BasicBlsScheme::verify(input, keypair.pk, 2, wrong) ){
        std::cout << "Signature is right" << std::endl;
    } else {
        std::cout << "Signature is wrong" << std::endl;
    };
    
    auto kp1 = BasicBlsScheme::generate_keys();
    auto kp2 = BasicBlsScheme::generate_keys();
    auto kp3 = BasicBlsScheme::generate_keys();

    std::string mmsg = "Light in the end of tonnel";

    std::vector<BasicBlsScheme::public_key_type> pks = {kp1.pk, kp2.pk, kp3.pk};
    auto apk = BasicBlsScheme::aggregate_public_keys(pks);

    std::vector<BasicBlsScheme::signature_type> signs = {
        BasicBlsScheme::sign(mmsg, kp1.sk),
        BasicBlsScheme::sign(mmsg, kp2.sk),
        BasicBlsScheme::sign(mmsg, kp3.sk),
    };
    auto Sigma = BasicBlsScheme::aggregate_signatures(signs);

    if( BasicBlsScheme::verify(mmsg, apk, 1, Sigma) ){
        std::cout << "Multi-signature is right" << std::endl;
    } else {
        std::cout << "Multi-signature is wrong" << std::endl;
    };

    if( BasicBlsScheme::verify(mmsg, kp1.pk, 1, Sigma) ){
        std::cout << "Multi-signature is right" << std::endl;
    } else {
        std::cout << "Multi-signature is wrong" << std::endl;
    };
    return 0;
}