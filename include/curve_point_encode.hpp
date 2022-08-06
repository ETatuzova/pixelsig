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

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::algebra;
using namespace nil::crypto3::multiprecision;
using namespace nil::crypto3::algebra::pairing;

template<typename FieldParams>
void tree_field_element(boost::property_tree::ptree &tree, std::string key, typename fields::detail::element_fp<FieldParams> e) {
    //std::cout<<"leaf"<<std::endl;

    tree.put(key,e.data);
}

template<typename FieldParams>
void push_field_element(boost::property_tree::ptree &node, typename fields::detail::element_fp<FieldParams> e) {
    //std::cout<<"push_leaf"<<std::endl;

    std::stringstream buffer;
    buffer << e.data;
    node.push_back(boost::property_tree::ptree::value_type("",buffer.str()));
}

template<typename FieldParams>
void push_field_element(boost::property_tree::ptree &node, typename fields::detail::element_fp2<FieldParams> e) {
    //std::cout<<"push 2"<<std::endl;

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
    //std::cout<<"push 3"<<std::endl;

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
    //std::cout<<"2 over 2"<<std::endl;

    boost::property_tree::ptree node0;
    push_field_element(node0, e.data[0]);
    node.push_back(boost::property_tree::ptree::value_type("",node0));

    boost::property_tree::ptree node1;
    push_field_element(node1, e.data[1]);
    node.push_back(boost::property_tree::ptree::value_type("",node1));
}

template<typename FieldParams>
void push_field_element(boost::property_tree::ptree &node, typename fields::detail::element_fp6_2over3<FieldParams> e) {
    //std::cout<<"2 over 3"<<std::endl;

    boost::property_tree::ptree node0;
    push_field_element(node0, e.data[0]);
    node.push_back(boost::property_tree::ptree::value_type("",node0));

    boost::property_tree::ptree node1;
    push_field_element(node1, e.data[1]);
    node.push_back(boost::property_tree::ptree::value_type("",node1));
}

template<typename FieldParams>
void push_field_element(boost::property_tree::ptree &node, typename fields::detail::element_fp6_3over2<FieldParams> e) {
    //std::cout<<"3 over 2"<<std::endl;

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
    //std::cout<<"2 over 3 over 2"<<std::endl;

    boost::property_tree::ptree node0;
    push_field_element(node0, e.data[0]);
    node.push_back(boost::property_tree::ptree::value_type("",node0));

    boost::property_tree::ptree node1;
    push_field_element(node1, e.data[1]);
    node.push_back(boost::property_tree::ptree::value_type("",node1));
}

template<typename CurveGroupValueType>
boost::property_tree::ptree tree_curve_group_element(CurveGroupValueType e) {
    boost::property_tree::ptree node;

    push_field_element(node, e.X);
    push_field_element(node, e.Y);
    push_field_element(node, e.Z);

    return node;
}

template<typename CurveGroupValueType>
std::string stringify_curve_group_element(CurveGroupValueType e) {
    boost::property_tree::ptree node = tree_curve_group_element(e);
    boost::property_tree::ptree tree;
    tree.add_child("r",node);
    
    std::stringstream ss;
    boost::property_tree::write_json(ss, tree);
//    boost::property_tree::write_json(std::cout, tree);
    std::string full_str = ss.str();
    return full_str.substr(11, full_str.length()-13);
}
