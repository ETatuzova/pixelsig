#include <iostream>

#include <nil/crypto3/algebra/fields/detail/element/fp.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp2.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp3.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp4.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp6_2over3.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp6_3over2.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp12_2over3over2.hpp>

#include <nil/crypto3/algebra/algorithms/pair.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

using namespace nil::crypto3::algebra::pairing;
using namespace nil::crypto3::algebra;
using namespace nil::crypto3::multiprecision;

template<typename FieldParams>
void print_field_element(typename fields::detail::element_fp<FieldParams> e) {
    std::cout << "fp: " << e.data << std::endl;
}

template<typename FieldParams>
void print_field_element(typename fields::detail::element_fp2<FieldParams> e) {
    std::cout << "fp2: " << e.data[0].data << " " << e.data[1].data << std::endl;
}

template<typename FieldParams>
void print_field_element(typename fields::detail::element_fp3<FieldParams> e) {
    std::cout << "fp3: " << e.data[0].data << " " << e.data[1].data << " " << e.data[2].data << std::endl;
}

template<typename FieldParams>
void print_field_element(typename fields::detail::element_fp4<FieldParams> e) {
    std::cout << "fp4: \n";
    print_field_element(e.data[0]);
    print_field_element(e.data[1]);
}

template<typename FieldParams>
void print_field_element(typename fields::detail::element_fp6_2over3<FieldParams> e) {
    std::cout << "fp6_2over3: \n";
    print_field_element(e.data[0]);
    print_field_element(e.data[1]);
}

template<typename FieldParams>
void print_field_element(typename fields::detail::element_fp6_3over2<FieldParams> e) {
    std::cout << "fp6_3over2: \n";
    print_field_element(e.data[0]);
    print_field_element(e.data[1]);
    print_field_element(e.data[2]);
}

template<typename FieldParams>
void print_field_element(typename fields::detail::element_fp12_2over3over2<FieldParams> e) {
    std::cout << "fp12_2over3over2: \n";;
    print_field_element(e.data[0]);
    print_field_element(e.data[1]);
}


template<typename CurveGroupValueType>
void print_curve_group_element(CurveGroupValueType e) {
    std::cout << "Group element: \n";;
    print_field_element(e.X);
    print_field_element(e.Y);
    print_field_element(e.Z);
}
