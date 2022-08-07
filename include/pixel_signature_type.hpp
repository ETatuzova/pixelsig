#include <curve_point_decode.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/iostreams/stream.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::algebra;
using namespace nil::crypto3::algebra::pairing;

template<typename CurveType> 
struct pixel_signature_type{
    using curve_type = CurveType;
    using g1_type = typename curve_type::template g1_type<>;
    using g2_type = typename curve_type::template g2_type<>;

    using g1_value_type = typename g1_type::value_type;
    using g2_value_type = typename g2_type::value_type;

    g1_value_type sigma1;
    g2_value_type sigma2;

    pixel_signature_type<curve_type>(std::string sig_str){
        boost::property_tree::ptree mynode;
        std::stringstream           strstream(sig_str);
//        boost::iostreams::stream<boost::iostreams::array_source> stream(sig_str, sig_str.length());
//        boost::property_tree::read_json(stream, mynode);

//                    std::istringstream sstr(sig_str);
        boost::property_tree::read_json(strstream, mynode);

        this->sigma1 = curve_point_init<g1_value_type>(mynode.get_child("s1"));
        this->sigma2 = curve_point_init<g2_value_type>(mynode.get_child("s2"));
    }
    pixel_signature_type<curve_type>(g1_value_type sigma1, g2_value_type sigma2){
        this->sigma1 = sigma1;
        this->sigma2 = sigma2;
    }

    operator std::string(){
        std::string  str1=stringify_curve_group_element(this->sigma1);
        std::string  str2=stringify_curve_group_element(this->sigma2);
        std::string  result = "{\"s1\":" + str1 + ",\"s2\":" + str2 + "}";
        return result;
    }
};
