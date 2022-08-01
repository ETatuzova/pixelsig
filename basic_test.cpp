template<typename Scheme, typename MsgRange>
void conformity_test(const std::vector<private_key<Scheme>> &sks,
                     const std::vector<MsgRange> &msgs,
                     const std::vector<typename public_key<Scheme>::signature_type> &etalon_sigs) {
    assert(std::distance(std::cbegin(sks), std::cend(sks)) > 1);
    assert(std::distance(std::cbegin(sks), std::cend(sks)) == std::distance(std::cbegin(msgs), std::cend(msgs)) &&
           (std::distance(std::cbegin(sks), std::cend(sks)) + 1) ==
               std::distance(std::cbegin(etalon_sigs), std::cend(etalon_sigs)));

    using scheme_type = Scheme;

    using signing_mode = typename ::nil::crypto3::pubkey::modes::isomorphic<scheme_type>::template bind<
        ::nil::crypto3::pubkey::signing_policy<Scheme>>::type;
    using verification_mode = typename ::nil::crypto3::pubkey::modes::isomorphic<scheme_type>::template bind<
        ::nil::crypto3::pubkey::verification_policy<scheme_type>>::type;
    using aggregation_mode = typename ::nil::crypto3::pubkey::modes::isomorphic<scheme_type>::template bind<
        ::nil::crypto3::pubkey::aggregation_policy<Scheme>>::type;
    using aggregate_verification_mode = typename ::nil::crypto3::pubkey::modes::isomorphic<scheme_type>::template bind<
        ::nil::crypto3::pubkey::aggregate_verification_policy<Scheme>>::type;

    using verification_acc_set = verification_accumulator_set<verification_mode>;
    using verification_acc = typename boost::mpl::front<typename verification_acc_set::features_type>::type;
    using signing_acc_set = signing_accumulator_set<signing_mode>;
    using signing_acc = typename boost::mpl::front<typename signing_acc_set::features_type>::type;
    using aggregation_acc_set = aggregation_accumulator_set<aggregation_mode>;
    using aggregation_acc = typename boost::mpl::front<typename aggregation_acc_set::features_type>::type;
    using aggregate_verification_acc_set = aggregate_verification_accumulator_set<aggregate_verification_mode>;
    using aggregate_verification_acc =
        typename boost::mpl::front<typename aggregate_verification_acc_set::features_type>::type;

    using privkey_type = private_key<scheme_type>;
    using pubkey_type = public_key<scheme_type>;

    using _privkey_type = typename privkey_type::private_key_type;
    using _pubkey_type = typename pubkey_type::public_key_type;
    using signature_type = typename pubkey_type::signature_type;
    using integral_type = typename _privkey_type::integral_type;

    using msg_type = MsgRange;

    std::random_device rd;
    std::mt19937 gen(rd());

    ///////////////////////////////////////////////////////////////////////////////
    // Sign
    auto sks_iter = sks.begin();
    auto msgs_iter = msgs.begin();
    auto etalon_sigs_iter = etalon_sigs.begin();

    // sign(range, prkey)
    // verify(range, pubkey)
    signature_type sig = ::nil::crypto3::sign(*msgs_iter, *sks_iter);
//    BOOST_CHECK_EQUAL(sig, *etalon_sigs_iter);
    const pubkey_type &pubkey = *sks_iter;
  //  BOOST_CHECK_EQUAL(static_cast<bool>(::nil::crypto3::verify(*msgs_iter, sig, pubkey)), true);

    // sign(first, last, prkey)
    // verify(first, last, pubkey)
    sig = ::nil::crypto3::sign(msgs_iter->begin(), msgs_iter->end(), *sks_iter);
//    BOOST_CHECK_EQUAL(sig, *etalon_sigs_iter);
//    BOOST_CHECK_EQUAL(static_cast<bool>(::nil::crypto3::verify(msgs_iter->begin(), msgs_iter->end(), sig, pubkey)),
//                      true);

    // sign(first, last, acc)
    // verify(first, last, acc)
    std::uniform_int_distribution<> distrib(0, msgs_iter->size() - 1);
    signing_acc_set sign_acc0(*sks_iter);
    auto part_msg_iter = msgs_iter->begin() + distrib(gen);
    ::nil::crypto3::sign<scheme_type>(msgs_iter->begin(), part_msg_iter, sign_acc0);
    sign_acc0(part_msg_iter, nil::crypto3::accumulators::iterator_last = msgs_iter->end());
    sig = boost::accumulators::extract_result<signing_acc>(sign_acc0);
//    BOOST_CHECK_EQUAL(sig, *etalon_sigs_iter);
    verification_acc_set verify_acc0(pubkey, nil::crypto3::accumulators::signature = sig);
    ::nil::crypto3::verify<scheme_type>(msgs_iter->begin(), part_msg_iter, verify_acc0);
    verify_acc0(part_msg_iter, nil::crypto3::accumulators::iterator_last = msgs_iter->end());
//    BOOST_CHECK_EQUAL(boost::accumulators::extract_result<verification_acc>(verify_acc0), true);

    // sign(range, acc)
    // verify(range, acc)
    signing_acc_set sign_acc1(*sks_iter);
    msg_type part_msg;
    std::copy(msgs_iter->begin(), part_msg_iter, std::back_inserter(part_msg));
    ::nil::crypto3::sign<scheme_type>(part_msg, sign_acc1);
    part_msg.clear();
    std::copy(part_msg_iter, msgs_iter->end(), std::back_inserter(part_msg));
    sign_acc1(part_msg);
    sig = boost::accumulators::extract_result<signing_acc>(sign_acc1);
//    BOOST_CHECK_EQUAL(sig, *etalon_sigs_iter);
    verification_acc_set verify_acc1(pubkey, nil::crypto3::accumulators::signature = sig);
    part_msg.clear();
    std::copy(msgs_iter->begin(), part_msg_iter, std::back_inserter(part_msg));
    ::nil::crypto3::verify<scheme_type>(part_msg, verify_acc1);
    part_msg.clear();
    std::copy(part_msg_iter, msgs_iter->end(), std::back_inserter(part_msg));
    verify_acc1(part_msg);
//    BOOST_CHECK_EQUAL(boost::accumulators::extract_result<verification_acc>(verify_acc1), true);

    // sign(range, prkey, out)
    // verify(range, pubkey, out)
    std::vector<signature_type> sig_out;
    ::nil::crypto3::sign(*msgs_iter, *sks_iter, std::back_inserter(sig_out));
//    BOOST_CHECK_EQUAL(sig_out.back(), *etalon_sigs_iter);
    std::vector<bool> bool_out;
    ::nil::crypto3::verify(*msgs_iter, sig_out.back(), pubkey, std::back_inserter(bool_out));
//    BOOST_CHECK_EQUAL(bool_out.back(), true);

    // sign(first, last, prkey, out)
    // verify(first, last, pubkey, out)
    ::nil::crypto3::sign(msgs_iter->begin(), msgs_iter->end(), *sks_iter, std::back_inserter(sig_out));
//    BOOST_CHECK_EQUAL(sig_out.back(), *etalon_sigs_iter);
    ::nil::crypto3::verify(msgs_iter->begin(), msgs_iter->end(), sig_out.back(), pubkey, std::back_inserter(bool_out));
//    BOOST_CHECK_EQUAL(bool_out.back(), true);

    sks_iter++;
    msgs_iter++;
    etalon_sigs_iter++;

    ///////////////////////////////////////////////////////////////////////////////
    // Agregate
    std::vector<const pubkey_type *> pks;
    std::vector<signature_type> sigs;

    pks.emplace_back(&*sks_iter);
    sigs.emplace_back(nil::crypto3::sign(*msgs_iter, *sks_iter));

//    BOOST_CHECK_EQUAL(sigs.back(), *etalon_sigs_iter);
    //BOOST_CHECK_EQUAL(static_cast<bool>(::nil::crypto3::verify(*msgs_iter, sigs.back(), *pks.back())), true);

    // TODO: add aggregate call with iterator output
    auto agg_acc = aggregation_acc_set();
    ::nil::crypto3::aggregate<scheme_type>(sigs, agg_acc);
    // ::nil::crypto3::aggregate<scheme_type>(sigs.end() - 1, sigs.end(), agg_acc);

    auto agg_ver_acc = aggregate_verification_acc_set(etalon_sigs.back());
    ::nil::crypto3::aggregate_verify<scheme_type>(*msgs_iter, *pks.back(), agg_ver_acc);

    sks_iter++;
    msgs_iter++;
    etalon_sigs_iter++;

    while (sks_iter != sks.end() && msgs_iter != msgs.end() && etalon_sigs_iter != (etalon_sigs.end() - 1)) {
        pks.emplace_back(&*sks_iter);
        sigs.emplace_back(nil::crypto3::sign(*msgs_iter, *sks_iter));

//        BOOST_CHECK_EQUAL(sigs.back(), *etalon_sigs_iter);
//        BOOST_CHECK_EQUAL(static_cast<bool>(::nil::crypto3::verify(*msgs_iter, sigs.back(), *pks.back())), true);

        ::nil::crypto3::aggregate<scheme_type>(sigs.end() - 1, sigs.end(), agg_acc);
        ::nil::crypto3::aggregate_verify<scheme_type>(*msgs_iter, *pks.back(), agg_ver_acc);

        sks_iter++;
        msgs_iter++;
        etalon_sigs_iter++;
    }

    signature_type agg_sig = ::nil::crypto3::aggregate<scheme_type>(sigs);
    std::vector<signature_type> agg_sig_out;
    ::nil::crypto3::aggregate<scheme_type>(sigs, std::back_inserter(agg_sig_out));
/*    BOOST_CHECK_EQUAL(agg_sig, *etalon_sigs_iter);
    BOOST_CHECK_EQUAL(agg_sig_out.back(), *etalon_sigs_iter);
    BOOST_CHECK_EQUAL(boost::accumulators::extract_result<aggregation_acc>(agg_acc), *etalon_sigs_iter);
    BOOST_CHECK_EQUAL(etalon_sigs.back(), *etalon_sigs_iter);*/

    // TODO: extend public interface to be able to supply signature into accumulator
    agg_ver_acc(agg_sig);
//    ::nil::crypto3::aggregate_verify<scheme_type>(agg_sig, agg_ver_acc);
    auto res = boost::accumulators::extract_result<aggregate_verification_acc>(agg_ver_acc);
//    BOOST_CHECK_EQUAL(res, true);
}
