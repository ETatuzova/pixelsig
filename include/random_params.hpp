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

using namespace nil::crypto3;
using namespace nil::crypto3::algebra;
using namespace nil::crypto3::multiprecision;
using namespace nil::crypto3::algebra::pairing;

template<typename CurveType>
struct pixel_basic_random_params{
    using self = pixel_basic_random_params<CurveType>;
    using curve_type = CurveType;

    using g1_type = typename curve_type::template g1_type<>;
    using g2_type = typename curve_type::template g2_type<>;
    using gt_type = typename curve_type::gt_type;
    using fr_type = typename curve_type::scalar_field_type;

    using g1_value_type = typename g1_type::value_type;
    using g2_value_type = typename g2_type::value_type;

    static int         T;  // maximum signature rounds;
    static g1_value_type g1;
    static g2_value_type g2; // generator of G2
    static g1_value_type h;  // constant h
    static g1_value_type F1; // constant F1
};

template<typename CurveType> int pixel_basic_random_params<CurveType>::T = 8;
template<typename CurveType> 
    typename pixel_basic_random_params<CurveType>::g1_value_type pixel_basic_random_params<CurveType>::g1 = random_element<typename CurveType::template g1_type<>>();
template<typename CurveType> 
    typename pixel_basic_random_params<CurveType>::g2_value_type pixel_basic_random_params<CurveType>::g2 = random_element<typename CurveType::template g2_type<>>();
template<typename CurveType> 
    typename pixel_basic_random_params<CurveType>::g1_value_type pixel_basic_random_params<CurveType>::h = random_element<typename CurveType::template g1_type<>>();
template<typename CurveType> 
    typename pixel_basic_random_params<CurveType>::g1_value_type pixel_basic_random_params<CurveType>::F1 = random_element<typename CurveType::template g1_type<>>();