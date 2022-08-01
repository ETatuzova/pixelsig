#include <nil/crypto3/hash/md5.hpp>
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


int main(int argc, char *argv[]) {
    pixel_parent_scheme<pixel_basic_scheme<fields::alt_bn128_fq<254>, fields::alt_bn128_fq<254>, void*, void*>,void*> basic_sig_scheme;
    pixel_parent_scheme<pixel_et_scheme<void*, void*, void*, void*>,void*> et_sig_scheme;
    void *msg = NULL;

    std::cout << "My first verify=" << basic_sig_scheme.verify(msg, NULL, NULL) << std::endl;
    std::cout << "My second verify=" << et_sig_scheme.verify(msg, NULL, NULL) << std::endl;

    std::string input = "Hello, Monday evening!";
    std::string out = hash<hashes::md5>(input.begin(), input.end());
    std::cout << out << std::endl;
}