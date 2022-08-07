#ifndef CURVE_POINT_DECODE
#define CURVE_POINT_DECODE

#include <nil/crypto3/algebra/algorithms/pair.hpp>
#include <nil/crypto3/algebra/type_traits.hpp>
#include <nil/crypto3/multiprecision/cpp_int.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::algebra;
using namespace nil::crypto3::algebra::pairing;
using namespace nil::crypto3::algebra::fields;

template<typename ElementType>
struct field_element_init;

template<typename FieldParams>
struct field_element_init<fields::detail::element_fp<FieldParams>> {
    using element_type = fields::detail::element_fp<FieldParams>;

    template<typename ElementData>
    static inline element_type process(const ElementData &element_data) {
        return element_type(typename element_type::integral_type(element_data.second.data()));
    }
};

template<typename FieldParams>
struct field_element_init<fields::detail::element_fp2<FieldParams>> {
    using element_type = fields::detail::element_fp2<FieldParams>;

    template<typename ElementData>
    static inline element_type process(const ElementData &element_data) {
        // element_fp
        using underlying_type = typename element_type::underlying_type;

        std::array<underlying_type, 2> element_values;
        auto i = 0;
        for (auto &element_value : element_data.second) {
            element_values[i++] = field_element_init<underlying_type>::process(element_value);
        }
        return element_type(element_values[0], element_values[1]);
    }
};

template<typename FieldParams>
struct field_element_init<fields::detail::element_fp3<FieldParams>> {
    using element_type = fields::detail::element_fp3<FieldParams>;

    template<typename ElementData>
    static inline element_type process(const ElementData &element_data) {
        // element_fp
        using underlying_type = typename element_type::underlying_type;

        std::array<underlying_type, 3> element_values;
        auto i = 0;
        for (auto &element_value : element_data.second) {
            element_values[i++] = field_element_init<underlying_type>::process(element_value);
        }
        return element_type(element_values[0], element_values[1], element_values[2]);
    }
};

template<typename FieldParams>
struct field_element_init<fields::detail::element_fp4<FieldParams>> {
    using element_type = fields::detail::element_fp4<FieldParams>;

    template<typename ElementData>
    static inline element_type process(const ElementData &element_data) {
        // element_fp2 over element_fp
        using underlying_type = typename element_type::underlying_type;

        std::array<underlying_type, 2> element_values;
        auto i = 0;
        for (auto &element_value : element_data.second) {
            element_values[i++] = field_element_init<underlying_type>::process(element_value);
        }
        return element_type(element_values[0], element_values[1]);
    }
};

template<typename FieldParams>
struct field_element_init<fields::detail::element_fp6_2over3<FieldParams>> {
    using element_type = fields::detail::element_fp6_2over3<FieldParams>;

    template<typename ElementData>
    static inline element_type process(const ElementData &element_data) {
        // element_fp3 over element_fp
        using underlying_type = typename element_type::underlying_type;

        std::array<underlying_type, 2> element_values;
        auto i = 0;
        for (auto &element_value : element_data.second) {
            element_values[i++] = field_element_init<underlying_type>::process(element_value);
        }
        return element_type(element_values[0], element_values[1]);
    }
};

template<typename FieldParams>
struct field_element_init<fields::detail::element_fp12_2over3over2<FieldParams>> {
    using element_type = fields::detail::element_fp12_2over3over2<FieldParams>;

    template<typename ElementData>
    static inline element_type process(const ElementData &element_data) {
        // element_fp3 over element_fp2 over element_fp
        using underlying_type_3over2 = typename element_type::underlying_type;
        // element_fp2 over element_fp
        using underlying_type = typename underlying_type_3over2::underlying_type;

        std::array<underlying_type_3over2, 2> element_values;
        std::array<underlying_type, 3> underlying_element_values;
        auto i = 0;
        for (auto &elem_3over2 : element_data.second) {
            auto j = 0;
            for (auto &elem_fp2 : elem_3over2.second) {
                underlying_element_values[j++] = field_element_init<underlying_type>::process(elem_fp2);
            }
            element_values[i++] = underlying_type_3over2(underlying_element_values[0], underlying_element_values[1],
                                                         underlying_element_values[2]);
        }
        return element_type(element_values[0], element_values[1]);
    }
};

template<typename CurveGroupValue, typename PointData>
CurveGroupValue curve_point_init(const PointData &point_data) {
    using group_value_type = CurveGroupValue;
    using field_value_type = typename group_value_type::field_type::value_type;

    std::array<field_value_type, 3> coordinates;
    auto i = 0;
    for (auto &coordinate : point_data) {
        coordinates[i++] = field_element_init<field_value_type>::process(coordinate);
    }
    return group_value_type(coordinates[0], coordinates[1], coordinates[2]);
}

#endif