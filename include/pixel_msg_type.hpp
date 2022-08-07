template<typename CurveType, typename HashType>
struct pixel_msg_type{
    using curve_type =      CurveType;
    using fr_type =         typename curve_type::scalar_field_type;
    using fr_value_type =   typename fr_type::value_type;

    fr_value_type           M;

    pixel_msg_type<CurveType, HashType>(std::string msg){
        std::string h = hash<HashType>(msg);

        BaseConverter conv = BaseConverter::HexToDecimalConverter();

        boost::to_upper(h);
        std::string dec = conv.Convert(h);
        this->M = typename fr_value_type::integral_type(dec);
    }
};

