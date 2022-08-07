#ifndef __CURVE_GROUP_ENCODE_HPP__
#define __CURVE_GROUP_ENCODE_HPP__

#include <nil/crypto3/algebra/algorithms/pair.hpp>
#include <nil/crypto3/algebra/type_traits.hpp>
#include <nil/crypto3/multiprecision/cpp_int.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::algebra;
using namespace nil::crypto3::multiprecision;
using namespace nil::crypto3::algebra::pairing;
using namespace nil::crypto3::algebra::fields;

// fp
template<typename FieldParams>
    std::string stringify_field_element(typename fields::detail::element_fp<FieldParams> e) {
    std::stringstream ss;
    ss << '"' << e.data << '"';
    return ss.str();
}

//fp2
template<typename FieldParams>
std::string stringify_field_element(typename fields::detail::element_fp2<FieldParams> e) {
    std::stringstream ss;
    ss << "[\"" << e.data[0].data << "\",\"" << e.data[1].data << "\"]";
    return ss.str();
}

//fp3
template<typename FieldParams>
std::string stringify_field_element(typename fields::detail::element_fp3<FieldParams> e) {
    std::stringstream ss;
    ss << "[\"" << e.data[0].data << "\",\"" << e.data[1].data << "\",\"" << e.data[2].data << "\"]";
    return ss.str();
}

//fp4
template<typename FieldParams>
std::string stringify_field_element(typename fields::detail::element_fp4<FieldParams> e) {
    std::stringstream ss;
    ss << "[" << stringify_field_element(e.data[0]) << "," <<stringify_field_element(e.data[1]) << "]";
    return ss.str();
}

//fp6_2over3
template<typename FieldParams>
std::string stringify_field_element(typename fields::detail::element_fp6_2over3<FieldParams> e) {
    std::stringstream ss;
    ss << "[" << stringify_field_element(e.data[0]) << "," <<stringify_field_element(e.data[1]) << "]";
//    print_field_element(e.data[0]);
//    print_field_element(e.data[1]);
    return ss.str();
}

//fp6_3over2
template<typename FieldParams>
std::string stringify_field_element(typename fields::detail::element_fp6_3over2<FieldParams> e) {
    std::stringstream ss;
    ss << "[" << stringify_field_element(e.data[0]) << "," <<stringify_field_element(e.data[1]) <<"," <<stringify_field_element(e.data[2]) << "]";
//    print_field_element(e.data[0]);
//    print_field_element(e.data[1]);
//    print_field_element(e.data[2]);
    return ss.str();
}

template<typename FieldParams>
std::string stringify_field_element(typename fields::detail::element_fp12_2over3over2<FieldParams> e) {
    std::stringstream ss;
    ss << "[" << stringify_field_element(e.data[0]) << "," << stringify_field_element(e.data[0]) << "]";
//    print_field_element(e.data[0]);
//    print_field_element(e.data[1]);
    return ss.str();
}

template<typename CurveGroupValueType>
std::string stringify_curve_group_element(CurveGroupValueType e) {
    std::stringstream ss;
    ss << "[" << stringify_field_element(e.X) << "," << stringify_field_element(e.Y) << "," << stringify_field_element(e.Z) <<"]";
    return ss.str();
}

#endif