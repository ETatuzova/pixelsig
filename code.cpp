#include <nil/crypto3/hash/md5.hpp>
#include <nil/crypto3/hash/sha1.hpp>
#include <nil/crypto3/hash/sha.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <vector>
#include <string>
#include <utility>
#include <random>

#include <pixelsig.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::algebra;
using namespace nil::crypto3::pubkey;
using namespace nil::crypto3::hashes;
using namespace nil::crypto3::multiprecision;

typedef std::string signature_type;

int main(int argc, char *argv[]) {
    pixel_parent_scheme<pixel_basic_scheme<fields::alt_bn128_fq<254>, fields::alt_bn128_fq<254>>, std::string, signature_type, hashes::sha> basic_sig_scheme;
    pixel_parent_scheme<pixel_et_scheme<void*, void*>,std::string, signature_type, hashes::sha1> et_sig_scheme;
    std::string input = "Tuesday was great";

    signature_type s = basic_sig_scheme.sign(input, NULL);
    signature_type s2 = et_sig_scheme.sign(input, NULL);

    std::cout << "My first signature= " << s << std::endl;
    std::cout << "My second signature=" << s2 << std::endl;

    std::cout << "My first verify= " << basic_sig_scheme.verify(input, NULL, "") << std::endl;
    std::cout << "My second verify=" << et_sig_scheme.verify(input, NULL, "NULL") << std::endl;

    std::string out = hash<hashes::md5>(input.begin(), input.end());
    std::cout << out << std::endl;
}