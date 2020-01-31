-module(miner_witness_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").
-include_lib("blockchain/include/blockchain_vars.hrl").

-export([
    all/0
]).

-export([
    init_per_testcase/2,
    end_per_testcase/2,
    refresh_test/1
]).

-define(SFLOCS, [631210968910285823, 631210968909003263, 631210968912894463, 631210968907949567]).
-define(NYLOCS, [631243922668565503, 631243922671147007, 631243922895615999, 631243922665907711]).

%%--------------------------------------------------------------------
%% COMMON TEST CALLBACK FUNCTIONS
%%--------------------------------------------------------------------

%%--------------------------------------------------------------------
%% @public
%% @doc
%%   Running tests for this suite
%% @end
%%--------------------------------------------------------------------
all() ->
    [refresh_test].

init_per_testcase(TestCase, Config0) ->
    Config = miner_ct_utils:init_per_testcase(TestCase, Config0),
    Config.

end_per_testcase(TestCase, Config) ->
    miner_ct_utils:end_per_testcase(TestCase, Config).

%%--------------------------------------------------------------------
%% TEST CASES
%%--------------------------------------------------------------------
refresh_test(Config) ->
    CommonPOCVars = common_poc_vars(Config),
    run_dist_with_params(refresh_test, Config, maps:put(?poc_version, 7, CommonPOCVars)).

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------
run_dist_with_params(TestCase, Config, VarMap) ->
    ok = setup_dist_test(TestCase, Config, VarMap),
    %% Execute the test
    ok = exec_dist_test(TestCase, Config, VarMap),
    %% show the final receipt counter
    Miners = proplists:get_value(miners, Config),
    FinalReceiptMap = challenger_receipts_map(find_receipts(Miners)),
    ct:pal("FinalReceiptCounter: ~p", [receipt_counter(FinalReceiptMap)]),
    %% The test endeth here
    ok.

exec_dist_test(_, Config, VarMap) ->
    Miners = proplists:get_value(miners, Config),
    %% Print scores before we begin the test
    InitialScores = gateway_scores(Config),
    ct:pal("InitialScores: ~p", [InitialScores]),
    %% check that every miner has issued a challenge
    ?assert(check_all_miners_can_challenge(Miners)),
    %% Check that the receipts are growing ONLY for poc_v4
    %% More specifically, first receipt can have a single element path (beacon)
    %% but subsequent ones must have more than one element in the path, reason being
    %% the first receipt would have added witnesses and we should be able to make
    %% a next hop.
    case maps:get(?poc_version, VarMap, 1) of
        V when V > 3 ->
            %% Check that we have atleast more than one request
            %% If we have only one request, there's no guarantee
            %% that the paths would eventually grow
            ?assert(check_multiple_requests(Miners)),
            %% Ensure that there are minimum N + 1 receipts
            %% The extra receipt should have multi element path
            ?assert(check_atleast_k_receipts(Miners, length(Miners) + 1)),
            %% Now we can check whether we have path growth
            ?assert(check_eventual_path_growth(Miners)),
            %% Now we check whether the scores have grown
            FinalScores = gateway_scores(Config),
            ct:pal("FinalScores: ~p", [FinalScores]),
            ok;
        _ ->
            %% By this point, we have ensured that every miner
            %% has a valid request atleast once, we just check
            %% that we have N (length(Miners)) receipts.
            ?assert(check_atleast_k_receipts(Miners, length(Miners))),
            ok
    end,
    ok.

setup_dist_test(TestCase, Config, VarMap) ->
    Miners = proplists:get_value(miners, Config),
    MinerCount = length(Miners),
    {_, Locations} = lists:unzip(initialize_chain(Miners, TestCase, Config, VarMap)),
    GenesisBlock = get_genesis_block(Miners, Config),
    miner_fake_radio_backplane:start_link(45000, lists:zip(lists:seq(46001, 46000 + MinerCount), Locations)),
    timer:sleep(5000),
    true = load_genesis_block(GenesisBlock, Miners, Config),
    %% wait till height 50
    true = wait_until_height(Miners, 50),
    ok.

gen_locations(_TestCase, Addresses, VarMap) ->
    LocationJitter = case maps:get(?poc_version, VarMap, 1) of
                         V when V > 3 ->
                             100;
                         _ ->
                             1000000
                     end,

    Locs = lists:foldl(
             fun(I, Acc) ->
                     [h3:from_geo({37.780586, -122.469470 + I/LocationJitter}, 13)|Acc]
             end,
             [],
             lists:seq(1, length(Addresses))
            ),
    {Locs, Locs}.

initialize_chain(Miners, TestCase, Config, VarMap) ->
    Addresses = proplists:get_value(addresses, Config),
    N = proplists:get_value(num_consensus_members, Config),
    Curve = proplists:get_value(dkg_curve, Config),
    Keys = libp2p_crypto:generate_keys(ecc_compact),
    InitialVars = miner_ct_utils:make_vars(Keys, VarMap),
    InitialPaymentTransactions = [blockchain_txn_coinbase_v1:new(Addr, 5000) || Addr <- Addresses],
    {ActualLocations, ClaimedLocations} = gen_locations(TestCase, Addresses, VarMap),
    AddressesWithLocations = lists:zip(Addresses, ActualLocations),
    AddressesWithClaimedLocations = lists:zip(Addresses, ClaimedLocations),
    InitialGenGatewayTxns = [blockchain_txn_gen_gateway_v1:new(Addr, Addr, Loc, 0) || {Addr, Loc} <- AddressesWithLocations],
    InitialTransactions = InitialVars ++ InitialPaymentTransactions ++ InitialGenGatewayTxns,
    DKGResults = miner_ct_utils:pmap(
        fun(Miner) ->
            ct_rpc:call(Miner, miner_consensus_mgr, initial_dkg, [InitialTransactions, Addresses, N, Curve])
        end,
        Miners
    ),
    ct:pal("results ~p", [DKGResults]),
    ?assert(lists:all(fun(Res) -> Res == ok end, DKGResults)),
    AddressesWithClaimedLocations.

get_genesis_block(Miners, Config) ->
    RPCTimeout = proplists:get_value(rpc_timeout, Config),
    ct:pal("RPCTimeout: ~p", [RPCTimeout]),
    %% obtain the genesis block
    GenesisBlock = get_genesis_block_(Miners, RPCTimeout),
    ?assertNotEqual(undefined, GenesisBlock),
    GenesisBlock.

get_genesis_block_([Miner|Miners], RPCTimeout) ->
    case ct_rpc:call(Miner, blockchain_worker, blockchain, [], RPCTimeout) of
        {badrpc, Reason} ->
            ct:fail(Reason),
            get_genesis_block_(Miners ++ [Miner], RPCTimeout);
        undefined ->
            get_genesis_block_(Miners ++ [Miner], RPCTimeout);
        Chain ->
            {ok, GBlock} = rpc:call(Miner, blockchain, genesis_block, [Chain], RPCTimeout),
            GBlock
    end.


load_genesis_block(GenesisBlock, Miners, Config) ->
    RPCTimeout = proplists:get_value(rpc_timeout, Config),
    %% load the genesis block on all the nodes
    lists:foreach(
        fun(Miner) ->
                case ct_rpc:call(Miner, miner_consensus_mgr, in_consensus, [], RPCTimeout) of
                    true ->
                        ok;
                    false ->
                        Res = ct_rpc:call(Miner, blockchain_worker,
                                          integrate_genesis_block, [GenesisBlock], RPCTimeout),
                        ct:pal("loading genesis ~p block on ~p ~p", [GenesisBlock, Miner, Res])
                end
        end,
        Miners
    ),

    timer:sleep(5000),

    true = wait_until_height(Miners, 1).

wait_until_height(Miners, Height) ->
    miner_ct_utils:wait_until(
      fun() ->
              Heights = lists:map(fun(Miner) ->
                                          case ct_rpc:call(Miner, blockchain_worker, blockchain, []) of
                                              undefined -> -1;
                                              {badrpc, _} -> -1;
                                              C ->
                                                  {ok, H} = ct_rpc:call(Miner, blockchain, height, [C]),
                                                  H
                                          end
                                  end,
                                  Miners),
              ct:pal("Heights: ~w", [Heights]),

              true == lists:all(fun(H) ->
                                        H >= Height
                                end,
                                Heights)
      end,
      60,
      timer:seconds(5)).

find_requests(Miners) ->
    [M | _] = Miners,
    Chain = ct_rpc:call(M, blockchain_worker, blockchain, []),
    Blocks = ct_rpc:call(M, blockchain, blocks, [Chain]),
    lists:flatten(lists:foldl(fun({_Hash, Block}, Acc) ->
                                      Txns = blockchain_block:transactions(Block),
                                      Requests = lists:filter(fun(T) ->
                                                                      blockchain_txn:type(T) == blockchain_txn_poc_request_v1
                                                              end,
                                                              Txns),
                                      [Requests | Acc]
                              end,
                              [],
                              maps:to_list(Blocks))).

find_receipts(Miners) ->
    [M | _] = Miners,
    Chain = ct_rpc:call(M, blockchain_worker, blockchain, []),
    Blocks = ct_rpc:call(M, blockchain, blocks, [Chain]),
    lists:flatten(lists:foldl(fun({_Hash, Block}, Acc) ->
                                      Txns = blockchain_block:transactions(Block),
                                      Height = blockchain_block:height(Block),
                                      Receipts = lists:filter(fun(T) ->
                                                                      blockchain_txn:type(T) == blockchain_txn_poc_receipts_v1
                                                              end,
                                                              Txns),
                                      TaggedReceipts = lists:map(fun(R) ->
                                                                         {Height, R}
                                                                 end,
                                                                 Receipts),
                                      TaggedReceipts ++ Acc
                              end,
                              [],
                              maps:to_list(Blocks))).

challenger_receipts_map(Receipts) ->
    lists:foldl(fun({_Height, Receipt}=R, Acc) ->
                        {ok, Challenger} = erl_angry_purple_tiger:animal_name(libp2p_crypto:bin_to_b58(blockchain_txn_poc_receipts_v1:challenger(Receipt))),
                        case maps:get(Challenger, Acc, undefined) of
                            undefined ->
                                maps:put(Challenger, [R], Acc);
                            List ->
                                maps:put(Challenger, lists:keysort(1, [R | List]), Acc)
                        end
                end,
                #{},
                Receipts).

request_counter(TotalRequests) ->
    lists:foldl(fun(Req, Acc) ->
                        {ok, Challenger} = erl_angry_purple_tiger:animal_name(libp2p_crypto:bin_to_b58(blockchain_txn_poc_request_v1:challenger(Req))),
                        case maps:get(Challenger, Acc, undefined) of
                            undefined ->
                                maps:put(Challenger, 1, Acc);
                            N when N > 0 ->
                                maps:put(Challenger, N + 1, Acc);
                            _ ->
                                maps:put(Challenger, 1, Acc)
                        end
                end,
                #{},
                TotalRequests).


check_all_miners_can_challenge(Miners) ->
    N = length(Miners),
    RequestCounter = request_counter(find_requests(Miners)),
    ct:pal("RequestCounter: ~p~n", [RequestCounter]),

    case N == maps:size(RequestCounter) of
        false ->
            ct:pal("Not every miner has issued a challenge...waiting..."),
            %% wait 50 more blocks?
            NewHeight = get_current_height(Miners),
            true = wait_until_height(Miners, NewHeight + 50),
            check_all_miners_can_challenge(Miners);
        true ->
            ct:pal("Got a challenge from each miner atleast once!"),
            true
    end.

get_current_height(Miners) ->
    [M | _] = Miners,
    Chain = ct_rpc:call(M, blockchain_worker, blockchain, []),
    {ok, Height} = ct_rpc:call(M, blockchain, height, [Chain]),
    Height.

check_eventual_path_growth(Miners) ->
    ReceiptMap = challenger_receipts_map(find_receipts(Miners)),
    case check_growing_paths(ReceiptMap, active_gateways(Miners), false) of
        false ->
            ct:pal("Not every poc appears to be growing...waiting..."),
            ct:pal("RequestCounter: ~p", [request_counter(find_requests(Miners))]),
            ct:pal("ReceiptCounter: ~p", [receipt_counter(ReceiptMap)]),
            %% wait 50 more blocks?
            Height = get_current_height(Miners),
            true = wait_until_height(Miners, Height + 50),
            check_eventual_path_growth(Miners);
        true ->
            ct:pal("Every poc eventually grows in path length!"),
            ct:pal("ReceiptCounter: ~p", [receipt_counter(ReceiptMap)]),
            true
    end.

check_growing_paths(ReceiptMap, ActiveGateways, PartitionFlag) ->
    Results = lists:foldl(fun({_Challenger, TaggedReceipts}, Acc) ->
                                  [{_, FirstReceipt} | Rest] = TaggedReceipts,
                                  %% It's possible that the first receipt itself has multiple elements path, I think
                                  RemainingGrowthCond = case PartitionFlag of
                                                            true ->
                                                                check_remaining_partitioned_grow(Rest, ActiveGateways);
                                                            false ->
                                                                check_remaining_grow(Rest)
                                                        end,
                                  Res = length(blockchain_txn_poc_receipts_v1:path(FirstReceipt)) >= 1 andalso RemainingGrowthCond,
                                  [Res | Acc]
                          end,
                          [],
                          maps:to_list(ReceiptMap)),
    lists:all(fun(R) -> R == true end, Results).

check_remaining_grow([]) ->
    true;
check_remaining_grow(TaggedReceipts) ->
    Res = lists:map(fun({_, Receipt}) ->
                            length(blockchain_txn_poc_receipts_v1:path(Receipt)) > 1
                    end,
                    TaggedReceipts),
    %% It's possible that even some of the remaining receipts have single path
    %% but there should eventually be some which have multi element paths
    lists:any(fun(R) -> R == true end, Res).

check_remaining_partitioned_grow([], _ActiveGateways) ->
    true;
check_remaining_partitioned_grow(TaggedReceipts, ActiveGateways) ->
    Res = lists:map(fun({_, Receipt}) ->
                            Path = blockchain_txn_poc_receipts_v1:path(Receipt),
                            PathLength = length(Path),
                            PathLength > 1 andalso PathLength =< 4 andalso check_partitions(Path, ActiveGateways)
                    end,
                    TaggedReceipts),
    %% It's possible that even some of the remaining receipts have single path
    %% but there should eventually be some which have multi element paths
    lists:any(fun(R) -> R == true end, Res).

check_partitions(Path, ActiveGateways) ->
    PathLocs = sets:from_list(lists:foldl(fun(Element, Acc) ->
                                                  Challengee = blockchain_poc_path_element_v1:challengee(Element),
                                                  ChallengeeGw = maps:get(Challengee, ActiveGateways),
                                                  ChallengeeLoc = blockchain_ledger_gateway_v2:location(ChallengeeGw),
                                                  [ChallengeeLoc | Acc]
                                          end,
                                          [],
                                          Path)),
    ct:pal("PathLocs: ~p", [sets:to_list(PathLocs)]),
    SFSet = sets:from_list(?SFLOCS),
    NYSet = sets:from_list(?NYLOCS),
    case sets:is_subset(PathLocs, SFSet) of
        true ->
            %% Path is in SF, check that it's not in NY
            sets:is_disjoint(PathLocs, NYSet);
        false ->
            %% Path is not in SF, check that it's only in NY
            sets:is_subset(PathLocs, NYSet) andalso sets:is_disjoint(PathLocs, SFSet)
    end.

check_multiple_requests(Miners) ->
    RequestCounter = request_counter(find_requests(Miners)),
    Cond = lists:sum(maps:values(RequestCounter)) > length(Miners),
    case Cond of
        false ->
            %% wait more
            ct:pal("Don't have multiple requests yet..."),
            ct:pal("RequestCounter: ~p", [RequestCounter]),
            case get_current_height(Miners) + 10 of
                N when N > 200 ->
                    false;
                N ->
                    true = wait_until_height(Miners, N),
                    check_multiple_requests(Miners)
            end;
        true ->
            true
    end.

check_atleast_k_receipts(Miners, K) ->
    ReceiptMap = challenger_receipts_map(find_receipts(Miners)),
    TotalReceipts = lists:foldl(fun(ReceiptList, Acc) ->
                                        length(ReceiptList) + Acc
                                end,
                                0,
                                maps:values(ReceiptMap)),
    ct:pal("TotalReceipts: ~p", [TotalReceipts]),
    case TotalReceipts >= K of
        false ->
            %% wait more
            ct:pal("Don't have receipts from each miner yet..."),
            ct:pal("ReceiptCounter: ~p", [receipt_counter(ReceiptMap)]),
            case get_current_height(Miners) + 10 of
                N when N > 200 ->
                    false;
                N ->
                    true = wait_until_height(Miners, N),
                    check_atleast_k_receipts(Miners, K)
            end;
        true ->
            true
    end.

receipt_counter(ReceiptMap) ->
    lists:foldl(fun({Name, ReceiptList}, Acc) ->
                        Counts = lists:map(fun({Height, ReceiptTxn}) ->
                                                   {Height, length(blockchain_txn_poc_receipts_v1:path(ReceiptTxn))}
                                           end,
                                           ReceiptList),
                        maps:put(Name, Counts, Acc)
                end,
                #{},
                maps:to_list(ReceiptMap)).

active_gateways([Miner | _]=_Miners) ->
    %% Get active gateways to get the locations
    Chain = ct_rpc:call(Miner, blockchain_worker, blockchain, []),
    Ledger = ct_rpc:call(Miner, blockchain, ledger, [Chain]),
    ct_rpc:call(Miner, blockchain_ledger_v1, active_gateways, [Ledger]).

gateway_scores(Config) ->
    [Miner | _] = proplists:get_value(miners, Config),
    Addresses = proplists:get_value(addresses, Config),
    Chain = ct_rpc:call(Miner, blockchain_worker, blockchain, []),
    Ledger = ct_rpc:call(Miner, blockchain, ledger, [Chain]),
    lists:foldl(fun(Address, Acc) ->
                        {ok, S} = ct_rpc:call(Miner, blockchain_ledger_v1, gateway_score, [Address, Ledger]),
                        {ok, Name} = erl_angry_purple_tiger:animal_name(libp2p_crypto:bin_to_b58(Address)),
                        maps:put(Name, S, Acc)
                end,
                #{},
                Addresses).

common_poc_vars(Config) ->
    N = proplists:get_value(num_consensus_members, Config),
    BlockTime = proplists:get_value(block_time, Config),
    Interval = proplists:get_value(election_interval, Config),
    BatchSize = proplists:get_value(batch_size, Config),
    Curve = proplists:get_value(dkg_curve, Config),
    %% Don't put the poc version here
    %% Add it to the map in the tests above
    #{?block_time => BlockTime,
      ?election_interval => Interval,
      ?num_consensus_members => N,
      ?batch_size => BatchSize,
      ?dkg_curve => Curve,
      ?poc_challenge_interval => 20,
      ?poc_v4_exclusion_cells => 10,
      ?poc_v4_parent_res => 11,
      ?poc_v4_prob_bad_rssi => 0.01,
      ?poc_v4_prob_count_wt => 0.3,
      ?poc_v4_prob_good_rssi => 1.0,
      ?poc_v4_prob_no_rssi => 0.5,
      ?poc_v4_prob_rssi_wt => 0.3,
      ?poc_v4_prob_time_wt => 0.3,
      ?poc_v4_randomness_wt => 0.1,
      ?poc_v4_target_challenge_age => 300,
      ?poc_v4_target_exclusion_cells => 6000,
      ?poc_v4_target_prob_edge_wt => 0.2,
      ?poc_v4_target_prob_score_wt => 0.8,
      ?poc_v4_target_score_curve => 5,
      ?poc_target_hex_parent_res => 5,
      ?poc_v5_target_prob_randomness_wt => 0.0,
      ?witness_refresh_interval => 11}.
