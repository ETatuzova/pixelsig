#include <cstddef>
/*!
    * @brief Pixel private key type
    * @tparam CurveType
    * This object can be used only once;
    * sign() function works only if used() is false. 
    * It sets used=true by use() method
    * Key should be deleted after update_keys() function call;
    * @see https://eprint.iacr.org/2019/514.pdf
    */

template<typename CurveType>
struct pixel_private_key_type{
    using curve_type = CurveType;
    using g1_type = typename curve_type::template g1_type<>;
    using g2_type = typename curve_type::template g2_type<>;

    using g1_value_type = typename g1_type::value_type;
    using g2_value_type = typename g2_type::value_type;

    using fr_type = typename curve_type::scalar_field_type;
    using fr_value_type = typename fr_type::value_type;

    // parts of private key
    g1_value_type hx;       // h^x --computed once
    g1_value_type hxFt0r;   // (h^x)*F(t, 0)^r
    g1_value_type F1r;      // F'^r
    g2_value_type g2r;      // g2^r
    int   t;

    void use(){ this->u = true; }
    bool used(){ return this->u; }
    private:
        bool u = false;
};

/*!
    * @brief Pixel private key type
    * @tparam CurveType
    * This object can be forever used for verifying signatures
    * @see https://eprint.iacr.org/2019/514.pdf
    */
template<typename CurveType>
struct pixel_public_key_type{
    using curve_type = CurveType;
    using g1_type = typename curve_type::template g1_type<>;
    using g2_type = typename curve_type::template g2_type<>;
    using gt_type = typename curve_type::gt_type;

    using g1_value_type = typename g1_type::value_type;
    using g2_value_type = typename g2_type::value_type;
    using gt_value_type = typename gt_type::value_type;

    g1_value_type proof;
    g2_value_type y;                // public key  y = g2^x
    gt_value_type hy;               // precomputed e(h,y)
};

/*!
    * @brief Pixel public-private key type
    * @tparam CurveType
    * @see https://eprint.iacr.org/2019/514.pdf
    */
template<typename CurveType>
struct pixel_keypair_type{
    using private_key_type = pixel_private_key_type<CurveType>;
    using public_key_type = pixel_public_key_type<CurveType>;

    private_key_type *sk;   // private key object
    public_key_type  pk;    // public key object

    ~pixel_keypair_type(){
        if(this->sk != NULL) delete[](sk);
    }
};
