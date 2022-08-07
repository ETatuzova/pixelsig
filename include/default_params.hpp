#include <nil/crypto3/algebra/algorithms/pair.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <curve_point_decode.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::algebra;
using namespace nil::crypto3::multiprecision;
using namespace nil::crypto3::algebra::pairing;

template <typename CurveType>
struct pixel_basic_default_params{
    using curve_type = CurveType;

    using g1_type = typename curve_type::template g1_type<>;
    using g2_type = typename curve_type::template g2_type<>;
    using gt_type = typename curve_type::gt_type;
    using fr_type = typename curve_type::scalar_field_type;

    using g1_value_type = typename g1_type::value_type;
    using g2_value_type = typename g2_type::value_type;

    static g1_value_type    g1;
    static g2_value_type    g2;
    static g1_value_type    h;
    static g1_value_type    F1;
    static int              T;

    static std::string params_path;
    static std::string curve_name;

    static void load(){
        const char *params_path = "../data/default_params.json";
        boost::property_tree::ptree string_data;
        boost::property_tree::read_json(params_path, string_data);
        boost::property_tree::ptree mynode = string_data.get_child("basic."+curve_name);

        g1 = curve_point_init<g1_value_type>(mynode.get_child("g1"));
        g2 = curve_point_init<g2_value_type>(mynode.get_child("g2"));
        h  = curve_point_init<g1_value_type>(mynode.get_child("h"));
        F1 = curve_point_init<g1_value_type>(mynode.get_child("F1"));
    }
};

template <typename CurveType>typename pixel_basic_default_params<CurveType>::g1_value_type pixel_basic_default_params<CurveType>::g1;
template <typename CurveType>typename pixel_basic_default_params<CurveType>::g2_value_type pixel_basic_default_params<CurveType>::g2;
template <typename CurveType>typename pixel_basic_default_params<CurveType>::g1_value_type pixel_basic_default_params<CurveType>::h;
template <typename CurveType>typename pixel_basic_default_params<CurveType>::g1_value_type pixel_basic_default_params<CurveType>::F1;
template <typename CurveType>int pixel_basic_default_params<CurveType>::T = 8;
template <typename CurveType>std::string pixel_basic_default_params<CurveType>::params_path = "../data/default_params.json";
template <typename CurveType>std::string pixel_basic_default_params<CurveType>::curve_name;
