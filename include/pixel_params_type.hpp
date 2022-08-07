template<typename CurveType, typename StaticParams>
struct pixel_basic_params{
    using curve_type = CurveType;
    using static_params = StaticParams;

    using g1_type = typename curve_type::template g1_type<>;
    using g1_value_type = typename g1_type::value_type;

    static void load(){
        static_params::load();
    }

    static g1_value_type F(int t){ //function F(t, 0){
        g1_value_type res;
        for( int i = 0; i < t; i++){
            res = res + static_params::g1;
        }
        return res;
    }
};