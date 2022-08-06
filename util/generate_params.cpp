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
void push_field_element(boost::property_tree::ptree &node, typename fields::detail::element_fp<FieldParams> e) {
    std::stringstream buffer;
    buffer << e.data;
    node.push_back(boost::property_tree::ptree::value_type("",buffer.str()));
}

template<typename FieldParams>
void push_field_element(boost::property_tree::ptree &node, typename fields::detail::element_fp2<FieldParams> e) {
    boost::property_tree::ptree mynode;

    std::stringstream buffer;
    buffer << e.data[0].data;
    mynode.push_back(boost::property_tree::ptree::value_type("",buffer.str()));

    std::stringstream buffer1;
    buffer1 << e.data[1].data;
    mynode.push_back(boost::property_tree::ptree::value_type("",buffer1.str()));

    node.push_back(boost::property_tree::ptree::value_type("",mynode));
}

template<typename FieldParams>
void push_field_element(boost::property_tree::ptree &node,  typename fields::detail::element_fp3<FieldParams> e) {
    boost::property_tree::ptree mynode;

    std::stringstream buffer;
    buffer << e.data[0].data;
    mynode.push_back(boost::property_tree::ptree::value_type("",buffer.str()));

    std::stringstream buffer1;
    buffer1 << e.data[1].data;
    mynode.push_back(boost::property_tree::ptree::value_type("",buffer1.str()));

    std::stringstream buffer2;
    buffer2 << e.data[2].data;
    mynode.push_back(boost::property_tree::ptree::value_type("",buffer2.str()));

    node.push_back(boost::property_tree::ptree::value_type("",mynode));
}

template<typename FieldParams>
void push_field_element(boost::property_tree::ptree &node, typename fields::detail::element_fp4<FieldParams> e) {
    boost::property_tree::ptree node0;
    push_field_element(node0, e.data[0]);
    node.push_back(boost::property_tree::ptree::value_type("",node0));

    boost::property_tree::ptree node1;
    push_field_element(node1, e.data[1]);
    node.push_back(boost::property_tree::ptree::value_type("",node1));
}

template<typename FieldParams>
void push_field_element(boost::property_tree::ptree &node, typename fields::detail::element_fp6_2over3<FieldParams> e) {
    boost::property_tree::ptree node0;
    push_field_element(node0, e.data[0]);
    node.push_back(boost::property_tree::ptree::value_type("",node0));

    boost::property_tree::ptree node1;
    push_field_element(node1, e.data[1]);
    node.push_back(boost::property_tree::ptree::value_type("",node1));
}

template<typename FieldParams>
void push_field_element(boost::property_tree::ptree &node, typename fields::detail::element_fp6_3over2<FieldParams> e) {
    boost::property_tree::ptree node0;
    push_field_element(node0, e.data[0]);
    node.push_back(boost::property_tree::ptree::value_type("",node0));

    boost::property_tree::ptree node1;
    push_field_element(node1, e.data[1]);
    node.push_back(boost::property_tree::ptree::value_type("",node1));

    boost::property_tree::ptree node2;
    push_field_element(node2, e.data[2]);
    node.push_back(boost::property_tree::ptree::value_type("",node2));
}

template<typename FieldParams>
void push_field_element(boost::property_tree::ptree &node, typename fields::detail::element_fp12_2over3over2<FieldParams> e) {
    boost::property_tree::ptree node0;
    push_field_element(node0, e.data[0]);
    node.push_back(boost::property_tree::ptree::value_type("",node0));

    boost::property_tree::ptree node1;
    push_field_element(node1, e.data[1]);
    node.push_back(boost::property_tree::ptree::value_type("",node1));
}

template<typename CurveGroupValueType>
void tree_curve_group_element(boost::property_tree::ptree &tree, std::string key, CurveGroupValueType e) {
    boost::property_tree::ptree node;

    push_field_element(node, e.X);
    push_field_element(node, e.Y);
    push_field_element(node, e.Z);

    tree.add_child(key, node);
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
    boost::property_tree::ptree tree;
    boost::property_tree::ptree basic;

    basic.put_child("bls12", paramsToTree<bls12params>());
    basic.put_child("mnt4", paramsToTree<mnt4params>());
    basic.put_child("mnt6", paramsToTree<mnt6params>());

    tree.put_child("basic", basic);

    boost::property_tree::write_json(std::cout, tree);
    return 0;
}
