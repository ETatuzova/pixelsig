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

#include <pixelsig.hpp>
#include <random_params.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::algebra;
using namespace nil::crypto3::pubkey;
using namespace nil::crypto3::hashes;
using namespace nil::crypto3::multiprecision;
using namespace nil::crypto3::algebra::pairing;

typedef std::string signature_type;

int main(int argc, char *argv[]) {
    pixel_parent_scheme<
        pixel_basic_scheme<
            curves::bls12<381>, 
            pixel_basic_params,
            pixel_basic_random_params
        >, 
        std::string, signature_type, hashes::sha
    > basic_sig_scheme;

    pixel_parent_scheme<
        pixel_basic_scheme<
            curves::mnt4<298>, 
            pixel_basic_params,
            pixel_basic_random_params
        >,
        std::string, signature_type, hashes::sha
    > basic_sig_scheme2;



    pixel_parent_scheme<pixel_et_scheme<curves::mnt4<298>>,std::string, signature_type, hashes::sha1> et_sig_scheme;
    std::string input = "Tuesday was great";

    basic_sig_scheme.setup();

    auto s = basic_sig_scheme.sign(input, NULL);
    auto s2 = et_sig_scheme.sign(input, NULL);

    std::cout << "My first signature= " << s << std::endl;
    std::cout << "My second signature=" << s2 << std::endl;

    std::cout << "My first verify= " << basic_sig_scheme.verify(input, NULL, "") << std::endl;
    std::cout << "My second verify=" << et_sig_scheme.verify(input, NULL, "NULL") << std::endl;

    std::string out = hash<hashes::md5>(input.begin(), input.end());
    std::cout << out << std::endl;
}