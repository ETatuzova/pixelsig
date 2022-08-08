#ifndef __UTIL_H__
#define __UTIL_H__

#include <base_converter.h>
#include <curve_point_encode.hpp>

template <typename CurveType>
typename CurveType::scalar_field_type::value_type hash2fr(std::string h){
    using curve_type =      CurveType;
    using fr_type =         typename curve_type::scalar_field_type;
    using fr_value_type =   typename fr_type::value_type;

    BaseConverter conv = BaseConverter::HexToDecimalConverter();

    boost::to_upper(h);
    std::string dec = conv.Convert(h);
    return typename fr_value_type::integral_type(dec);
}

#endif