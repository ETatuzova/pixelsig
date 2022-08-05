//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#include <boost/algorithm/string/case_conv.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int.hpp>
#include <iostream>
#include <iomanip>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>

#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/algebra/curves/curve25519.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/jubjub.hpp>

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/marshalling/algebra/types/curve_element.hpp>

#include <boost/locale.hpp>
#include <iostream>

#include <ctime>

using namespace std;

template<typename TIter>
void print_byteblob(TIter iter_begin, TIter iter_end) {
    for (TIter it = iter_begin; it != iter_end; it++) {
        std::cout << std::hex << int(*it) << std::endl;
    }
}

template<typename T>
void test_curve_element_big_endian(T val) {
    using namespace nil::crypto3::marshalling;

    using Endianness = nil::marshalling::option::big_endian;

    using unit_type = unsigned char;

    using curve_element_type = types::curve_element<nil::marshalling::field_type<Endianness>, typename T::group_type>;

    static_assert(nil::marshalling::is_curve_element<curve_element_type>::value);
    static_assert(nil::marshalling::is_compatible<T>::value);

    nil::marshalling::status_type status;
    std::vector<unit_type> cv = nil::marshalling::pack<Endianness>(val, status);

//    BOOST_CHECK(status == nil::marshalling::status_type::success);

    T test_val = nil::marshalling::pack<Endianness>(cv, status);

//    BOOST_CHECK(val == test_val);
//    BOOST_CHECK(status == nil::marshalling::status_type::success);
}

template<typename CurveGroup>
void test_curve_element() {
    std::cout << "Test curve element started"<< std::endl;
    std::cout << std::hex;
    std::cerr << std::hex;
    for (unsigned i = 0; i < 128; ++i) {
        if (!(i % 16) && i) {
            std::cout << std::dec << i << " tested" << std::endl;
        }
        typename CurveGroup::value_type val = nil::crypto3::algebra::random_element<CurveGroup>();
        test_curve_element_big_endian(val);
        // test_curve_element_little_endian(val);
    }
}

int main()
{
    using namespace boost::locale;

    test_curve_element<nil::crypto3::algebra::curves::bls12<381>::g1_type<>>();
}