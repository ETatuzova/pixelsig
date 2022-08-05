#include <iostream>
#include <random_params.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

using namespace std;

using namespace nil::crypto3;
using namespace nil::crypto3::algebra;
using namespace nil::crypto3::multiprecision;
using namespace nil::crypto3::algebra::pairing;

using bls12params = pixel_basic_random_params<curves::bls12<381>>;
using mnt4params =  pixel_basic_random_params<curves::mnt4<298>>;
using mnt6params = pixel_basic_random_params<curves::mnt6<298>>;

template<typename FieldParams>
void tree_field_element(boost::property_tree::ptree &tree, std::string key, typename fields::detail::element_fp<FieldParams> e) {
    tree.put(key,e.data);
}

template<typename FieldParams>
void tree_field_element(boost::property_tree::ptree &tree, std::string key, typename fields::detail::element_fp2<FieldParams> e) {
    tree.put(key+".0",e.data[0].data);
    tree.put(key+".1",e.data[1].data);
}

template<typename FieldParams>
void tree_field_element(boost::property_tree::ptree &tree, std::string key, typename fields::detail::element_fp3<FieldParams> e) {
    tree.put(key+".0",e.data[0].data);
    tree.put(key+".1",e.data[1].data);
    tree.put(key+".2",e.data[2].data);
}

template<typename FieldParams>
void tree_field_element(boost::property_tree::ptree &tree, std::string key, typename fields::detail::element_fp4<FieldParams> e) {
    tree_field_element(tree, key+".0", e.data[0]);
    tree_field_element(tree, key+".1", e.data[1]);
}

template<typename FieldParams>
void tree_field_element(boost::property_tree::ptree &tree, std::string key, typename fields::detail::element_fp6_2over3<FieldParams> e) {
    tree_field_element(tree, key+".0", e.data[0]);
    tree_field_element(tree, key+".1", e.data[1]);
}

template<typename FieldParams>
void tree_field_element(boost::property_tree::ptree &tree, std::string key, typename fields::detail::element_fp6_3over2<FieldParams> e) {
    tree_field_element(e.data[0]);
    tree_field_element(e.data[1]);
    tree_field_element(e.data[2]);
}

template<typename FieldParams>
void tree_field_element(boost::property_tree::ptree &tree, std::string key, typename fields::detail::element_fp12_2over3over2<FieldParams> e) {
    tree_field_element(e.data[0]);
    tree_field_element(e.data[1]);
}

template<typename CurveGroupValueType>
void tree_curve_group_element(boost::property_tree::ptree &tree, std::string key, CurveGroupValueType e) {
    tree_field_element(tree, key+".X", e.X);
    tree_field_element(tree, key+".Y", e.Y);
    tree_field_element(tree, key+".Z", e.Z);
}

template <typename params>
boost::property_tree::ptree paramsToTree(){
    boost::property_tree::ptree tree;

//    tree_curve_group_element(params::g2);
    tree_curve_group_element(tree, "g1", params::g1);
    tree_curve_group_element(tree, "g2", params::g2);
    tree_curve_group_element(tree, "h", params::h);
    tree_curve_group_element(tree, "F1", params::F1);
/*    tree.put("g1.X", params::g1.X.data);
    tree.put("g1.Y", params::g1.Y.data);
    tree.put("g1.Z", params::g1.Z.data);

    tree.put("g2.X.0", params::g2.X.data[0].data);
    tree.put("g2.X.1", params::g2.X.data[1].data);

    tree.put("g2.Y.0", params::g2.Y.data[0].data);
    tree.put("g2.Y.1", params::g2.Y.data[1].data);

    tree.put("g2.Z.0", params::g2.Z.data[0].data);
    tree.put("g2.Z.1", params::g2.Z.data[1].data);

    tree.put("h1.X", params::h.X.data);
    tree.put("h1.Y", params::h.Y.data);
    tree.put("h1.Z", params::h.Z.data);

    tree.put("h1.X", params::F1.X.data);
    tree.put("h1.Y", params::F1.Y.data);
    tree.put("h1.Z", params::F1.Z.data);

*/
    return tree;
}

const char *dst_path = "../data/default_params.json";

int main(int argc, char *argv[]) {
    std::cout << "Generate basic params" << std::endl;

    boost::property_tree::ptree tree;
    boost::property_tree::ptree basic;

    basic.put_child("bls12", paramsToTree<bls12params>());
    basic.put_child("mnt4", paramsToTree<mnt4params>());
    basic.put_child("mnt6", paramsToTree<mnt6params>());

    tree.put_child("basic", basic);

    std::ofstream dst_file;
    dst_file.open (dst_path);
    boost::property_tree::write_json(dst_file, tree);
    dst_file.close ();
    return 0;
}
