#include <iostream>
#include <random_params.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <curve_point_encode.hpp>

using namespace std;

using namespace nil::crypto3;
using namespace nil::crypto3::algebra;
using namespace nil::crypto3::multiprecision;
using namespace nil::crypto3::algebra::pairing;

using bls12params = pixel_basic_random_params<curves::bls12<381>>;
using mnt4params =  pixel_basic_random_params<curves::mnt4<298>>;
using mnt6params = pixel_basic_random_params<curves::mnt6<298>>;


const char *dst_path = "../data/default_params.json";

template <typename params>
boost::property_tree::ptree paramsToTree(){
    boost::property_tree::ptree tree;

//    tree_curve_group_element(params::g2);
    tree.add_child("g1",tree_curve_group_element(params::g1));
    tree.add_child("g2",tree_curve_group_element(params::g2));
    tree.add_child("h" ,tree_curve_group_element(params::h));
    tree.add_child("F1",tree_curve_group_element(params::F1));
/*    tree_curve_group_element(tree, "g1", params::g1);
    tree_curve_group_element(tree, "g2", params::g2);
    tree_curve_group_element(tree, "h", params::h);
    tree_curve_group_element(tree, "F1", params::F1);*/
    return tree;
}

int main(int argc, char *argv[]) {
    boost::property_tree::ptree tree;
    boost::property_tree::ptree basic;

    basic.put_child("bls12", paramsToTree<bls12params>());
//    basic.put_child("mnt4", paramsToTree<mnt4params>());
//    basic.put_child("mnt6", paramsToTree<mnt6params>());

    tree.put_child("basic", basic);

    boost::property_tree::write_json(std::cout, tree);
    return 0;
}
