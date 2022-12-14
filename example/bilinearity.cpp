//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
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
#include <iostream>

#include <nil/crypto3/algebra/fields/detail/element/fp.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp2.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp3.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp4.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp6_2over3.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp6_3over2.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp12_2over3over2.hpp>

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

using namespace nil::crypto3::algebra::pairing;
using namespace nil::crypto3::algebra;
using namespace nil::crypto3::multiprecision;

template<typename CurveType>
void bilinear_example() {
    using curve_type = CurveType;

    using g1_type = typename curve_type::template g1_type<>;
    using g2_type = typename curve_type::template g2_type<>;
    using gt_type = typename curve_type::gt_type;
    using fr_type = typename curve_type::scalar_field_type;

    using g1_value_type = typename g1_type::value_type;
    using g2_value_type = typename g2_type::value_type;
    using gt_value_type =  typename gt_type::value_type;
    using fr_value_type = typename fr_type::value_type;

    g1_value_type g1 = random_element<g1_type>();
//    std::cout << "G1 random element: ";
//    print_curve_group_element(g1);

    g2_value_type g2 = random_element<g2_type>();
//    std::cout << "G2 random element: ";
//    print_curve_group_element(g2);

    fr_value_type a = random_element<fr_type>();
//    std::cout << "Fr random element: ";
//    print_field_element(a);


    gt_value_type var1 = pair_reduced<curve_type>(a * g1, g2);
    gt_value_type var2 = pair_reduced<curve_type>(g1, a*g2);
    gt_value_type var3 = pair_reduced<curve_type>(g1, g2).pow(cpp_int(a.data));
    std::cout << "e(g1^a,g2), e(g1, g2^a), e(g1,g2)^a" << std::endl;
    print_field_element(var1);
    print_field_element(var2);
    print_field_element(var3);

    typename curve_type::gt_type::value_type gt_el1 = pair_reduced<curve_type>(g1, g2);
//    std::cout << "e(g1,g2): ";
//    print_field_element(gt_el1);

}

int main(int argc, char *argv[]) {
    bilinear_example<curves::mnt6<298>>();
    std::cout << "__________________________________________________________" << std::endl;
    bilinear_example<curves::mnt4<298>>();
    std::cout << "__________________________________________________________" << std::endl;
    bilinear_example<curves::bls12<381>>();
    std::cout << "__________________________________________________________" << std::endl;
}
