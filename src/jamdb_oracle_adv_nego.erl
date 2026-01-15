-module(jamdb_oracle_adv_nego).

%% Oracle Advanced Services Negotiation Protocol
%% Based on go-ora implementation with Diffie-Hellman key exchange

-export([negotiate/1, activate_encryption/2]).

-include("jamdb_oracle.hrl").

%% Debug logging helper
debug_log(false, _Format, _Args) ->
    ok;
debug_log(true, Format, Args) ->
    io:format("[jamdb_oracle_adv_nego] " ++ Format ++ "~n", Args).

%% Service type constants
-define(SERVICE_AUTH, 1).
-define(SERVICE_ENCRYPTION, 2).
-define(SERVICE_DATA_INTEGRITY, 3).
-define(SERVICE_SUPERVISOR, 4).

%% Encryption algorithm IDs (matching go-ora's Oracle protocol)
-define(ALGO_RC4_40, 1).
-define(ALGO_DES56C, 2).
-define(ALGO_RC4_256, 6).
-define(ALGO_RC4_56, 8).
-define(ALGO_RC4_128, 10).
-define(ALGO_3DES112, 11).
-define(ALGO_3DES168, 12).
-define(ALGO_AES128, 15).
-define(ALGO_AES192, 16).
-define(ALGO_AES256, 17).

%% Algorithm names (matches go-ora encrypt_service.go)
-define(ALGOS, [
    {?ALGO_RC4_40, "RC4_40"},
    {?ALGO_DES56C, "DES56C"},
    {?ALGO_RC4_256, "RC4_256"},
    {?ALGO_RC4_56, "RC4_56"},
    {?ALGO_RC4_128, "RC4_128"},
    {?ALGO_3DES112, "3DES112"},
    {?ALGO_3DES168, "3DES168"},
    {?ALGO_AES128, "AES128"},
    {?ALGO_AES192, "AES192"},
    {?ALGO_AES256, "AES256"}
]).

%% Negotiate advanced services with Oracle server
negotiate(#oraclient{socket = Socket, sdu = Length, version = Version, timeouts = Touts, debug = Debug} = State) ->
    debug_log(Debug, "Starting advanced services negotiation", []),
    %% Build and send negotiation request
    NegoPkt = build_nego_request(),
    {Packet, _Rest} = jamdb_oracle_tns_encoder:encode_packet(6, NegoPkt, Length, Version),

    debug_log(Debug, "Sending negotiation request (~p bytes)", [byte_size(Packet)]),
    case gen_tcp:send(Socket, Packet) of
        ok ->
            debug_log(Debug, "Negotiation request sent, waiting for response", []),
            %% Read server response
            {Tout, _ReadTout} = Touts,
            case gen_tcp:recv(Socket, 0, Tout) of
                {ok, Data} when byte_size(Data) >= 8 ->
                    <<_PacketSize:16, _Flags:16, PacketType:8, _PacketFlags:8, Rest/binary>> = Data,
                    debug_log(Debug, "Received response packet type ~p (~p bytes)", [PacketType, byte_size(Data)]),
                    case PacketType of
                        6 ->  %% DATA packet
                            <<_DataFlags:32, Response/binary>> = Rest,
                            case parse_nego_response(Response, State) of
                                {ok, State2, NeedsDH} ->
                                    debug_log(Debug, "Negotiation response parsed successfully", []),
                                    case NeedsDH of
                                        {true, DHParams} ->
                                            debug_log(Debug, "Server requests DH key exchange", []),
                                            %% Server wants DH key exchange
                                            perform_dh_exchange(Socket, Length, Touts, DHParams, State2);
                                        false ->
                                            debug_log(Debug, "No DH key exchange required", []),
                                            %% No DH needed, continue
                                            {ok, State2}
                                    end;
                                {error, Reason} ->
                                    debug_log(Debug, "Failed to parse negotiation response: ~p", [Reason]),
                                    {error, Reason}
                            end;
                        _ when PacketType >= 1 andalso PacketType =< 19 ->
                            debug_log(Debug, "Unexpected packet type: ~p", [PacketType]),
                            {error, {unexpected_packet_type, PacketType}};
                        _ ->
                            debug_log(Debug, "Invalid packet", []),
                            {error, invalid_packet}
                    end;
                {ok, _Data} ->
                    debug_log(Debug, "Short packet received", []),
                    {error, short_packet};
                {error, Reason} ->
                    debug_log(Debug, "Error receiving negotiation response: ~p", [Reason]),
                    {error, Reason}
            end;
        {error, Reason} ->
            debug_log(Debug, "Failed to send negotiation request: ~p", [Reason]),
            {error, Reason}
    end.

%% Perform Diffie-Hellman key exchange
perform_dh_exchange(Socket, Length, _Touts, DHParams, #oraclient{version = Version, debug = Debug} = State) ->
    debug_log(Debug, "Performing DH key exchange", []),

    case validate_dh_params(DHParams) of
        {error, Reason} ->
            debug_log(Debug, "Invalid DH parameters: ~p", [Reason]),
            {error, {invalid_dh_params, Reason}};
        ok ->
            {IntegrityAlgoId, Gen, Prime, ServerPubKey, IV} = DHParams,
            debug_log(Debug, "DH params - IntegrityAlgo: ~p, Prime size: ~p, IV size: ~p",
                     [IntegrityAlgoId, byte_size(Prime), byte_size(IV)]),

            %% Calculate expected byte length from prime (matches go-ora byteLen calculation)
            ByteLen = byte_size(Prime),

            %% Generate client private key with correct length
            PrivateKey = crypto:strong_rand_bytes(ByteLen),
            PrivateKeyInt = binary:decode_unsigned(PrivateKey),
            GenInt = binary:decode_unsigned(Gen),
            PrimeInt = binary:decode_unsigned(Prime),

            debug_log(Debug, "Generating client public key", []),
            %% ClientPubKey = Gen^PrivateKey mod Prime
            ClientPubKeyRaw = crypto:mod_pow(GenInt, PrivateKeyInt, PrimeInt),

            %% Pad with leading zeros to match expected byte length (like go-ora FillBytes)
            ClientPubKey = case byte_size(ClientPubKeyRaw) of
                Len when Len < ByteLen ->
                    PaddingSize = ByteLen - Len,
                    <<0:(PaddingSize*8), ClientPubKeyRaw/binary>>;
                _ ->
                    ClientPubKeyRaw
            end,

            debug_log(Debug, "Client public key size: ~p bytes", [byte_size(ClientPubKey)]),

            %% Build DH response packet
            DHResponse = build_dh_response(ClientPubKey),
            {Packet, _} = jamdb_oracle_tns_encoder:encode_packet(6, DHResponse, Length, Version),

            debug_log(Debug, "Sending DH response (~p bytes)", [byte_size(Packet)]),
            case gen_tcp:send(Socket, Packet) of
                ok ->
                    debug_log(Debug, "DH response sent, calculating shared secret", []),
                    %% Calculate shared secret: SharedKey = ServerPubKey^PrivateKey mod Prime
                    ServerPubKeyInt = binary:decode_unsigned(ServerPubKey),
                    SharedKeyRaw = crypto:mod_pow(ServerPubKeyInt, PrivateKeyInt, PrimeInt),

                    %% Pad with leading zeros to match expected byte length (like go-ora FillBytes)
                    SharedKey = case byte_size(SharedKeyRaw) of
                        RawLen when RawLen < ByteLen ->
                            Padding = ByteLen - RawLen,
                            <<0:(Padding*8), SharedKeyRaw/binary>>;
                        _ ->
                            SharedKeyRaw
                        end,

                    debug_log(Debug, "Shared secret calculated (~p bytes)", [byte_size(SharedKey)]),

                    %% Store full session key (init_encryption will slice it as needed per algorithm)
                    StateWithKey = State#oraclient{auth = {SharedKey, IV}, integrity_algo = IntegrityAlgoId},
                    {ok, StateWithKey};
                {error, Reason} ->
                    debug_log(Debug, "Failed to send DH response: ~p", [Reason]),
                    {error, Reason}
            end
    end.

%% Build DH response packet
build_dh_response(ClientPubKey) ->
    Magic = 16#DEADBEEF,
    Version = 16#0B200200,
    ServiceCount = 1,
    ErrorFlags = 0,

    %% Service 3 (Data Integrity) header
    ServiceType = ?SERVICE_DATA_INTEGRITY,
    SubPacketCount = 1,
    ErrorCode = 0,

    %% Build service data with client public key (BYTES subpacket has no length prefix)
    PubKeyLen = byte_size(ClientPubKey),
    ServiceData = <<
        PubKeyLen:16/big,      %% Packet length (just the data size, no header included)
        1:16/big,              %% Type 1 = bytes
        ClientPubKey/binary    %% Client public key (no length prefix!)
    >>,

    Service = <<
        ServiceType:16/big,
        SubPacketCount:16/big,
        ErrorCode:32/big,
        ServiceData/binary
    >>,

    TotalLength = 13 + byte_size(Service),

    <<
        Magic:32/big,
        TotalLength:16/big,
        Version:32/big,
        ServiceCount:16/big,
        ErrorFlags:8,
        Service/binary
    >>.

%% Build negotiation request packet matching go-ora format
build_nego_request() ->
    Magic = 16#DEADBEEF,
    Version = 16#0B200200,
    ServiceCount = 4,
    ErrorFlags = 0,

    %% Build service data (order matters: Supervisor, Auth, Encrypt, Integrity)
    SupervisorData = build_supervisor_service(),
    AuthData = build_auth_service(),
    %% Match go-ora's algorithm list: RC4 and AES variants
    EncryptData = build_encryption_service([0, ?ALGO_RC4_40, ?ALGO_RC4_56, ?ALGO_RC4_128,
                                            ?ALGO_RC4_256, ?ALGO_DES56C, ?ALGO_AES128,
                                            ?ALGO_AES192, ?ALGO_AES256]),
    %% go-ora data integrity with empty list and useDefault=true includes all: [0, 1, 3, 4, 5, 6]
    IntegrityData = build_integrity_service([0, 1, 3, 4, 5, 6]),

    AllServices = <<SupervisorData/binary, AuthData/binary, EncryptData/binary, IntegrityData/binary>>,
    TotalLength = 13 + byte_size(AllServices),

    <<
        Magic:32/big,
        TotalLength:16/big,
        Version:32/big,
        ServiceCount:16/big,
        ErrorFlags:8,
        AllServices/binary
    >>.

%% Supervisor service
build_supervisor_service() ->
    ServiceType = ?SERVICE_SUPERVISOR,
    SubPacketCount = 3,
    ErrorCode = 0,
    Version = 16#0B200200,

    %% CID (8 bytes) - go-ora uses {0, 0, 16, 28, 102, 236, 40, 234}
    CID = <<0, 0, 16, 28, 102, 236, 40, 234>>,

    %% Service array: [4, 1, 2, 3] = supervisor, auth, encryption, data_integrity
    ServArray = [4, 1, 2, 3],
    ServArrayBin = << <<S:16/big>> || S <- ServArray >>,
    ServArrayLen = 10 + length(ServArray) * 2,  %% 4 (DEADBEEF) + 2 (magic) + 4 (count) + elements

    ServiceData = <<
        %% Version sub-packet (packet_len=4, packet_type=5, version)
        4:16/big, 5:16/big, Version:32/big,
        %% CID sub-packet (packet_len=8, packet_type=1, data)
        8:16/big, 1:16/big, CID/binary,
        %% Service array sub-packet (packet_len, packet_type=1, DEADBEEF, 3, count, array)
        ServArrayLen:16/big, 1:16/big,
        16#DEADBEEF:32/big, 3:16/big, (length(ServArray)):32/big,
        ServArrayBin/binary
    >>,

    <<ServiceType:16/big, SubPacketCount:16/big, ErrorCode:32/big, ServiceData/binary>>.

%% Auth service (matches go-ora auth_service.go writeServiceData)
build_auth_service() ->
    ServiceType = ?SERVICE_AUTH,
    ErrorCode = 0,
    Version = 16#0B200200,

    %% Auth service IDs and names: [0, 1, 1, 2] for ["", "NTS", "KERBEROS5", "TCPS"]
    AuthServices = [{0, <<>>}, {1, <<"NTS">>}, {1, <<"KERBEROS5">>}, {2, <<"TCPS">>}],

    %% SubPacket count = 3 + (num_services * 2): each service = UB1 + String
    SubPacketCount = 3 + (length(AuthServices) * 2),

    %% Build auth service sub-packets (UB1 sub-packet + String sub-packet for each)
    AuthSubPackets = lists:foldl(fun({ID, Name}, Acc) ->
        NameLen = byte_size(Name),
        %% UB1 sub-packet: packet_len=1, packet_type=2, id
        UB1SubPacket = <<1:16/big, 2:16/big, ID:8>>,
        %% String sub-packet: packet_len=len, packet_type=0, name
        StringSubPacket = <<NameLen:16/big, 0:16/big, Name/binary>>,
        <<Acc/binary, UB1SubPacket/binary, StringSubPacket/binary>>
    end, <<>>, AuthServices),

    ServiceData = <<
        %% Version sub-packet (packet_len=4, packet_type=5, version)
        4:16/big, 5:16/big, Version:32/big,
        %% UB2 sub-packet (packet_len=2, packet_type=3, value=0xE0E1)
        2:16/big, 3:16/big, 16#E0E1:16/big,
        %% Status sub-packet (packet_len=2, packet_type=6, status=0xFCFF)
        2:16/big, 6:16/big, 16#FCFF:16/big,
        %% Auth service sub-packets (UB1 + String for each)
        AuthSubPackets/binary
    >>,

    <<ServiceType:16/big, SubPacketCount:16/big, ErrorCode:32/big, ServiceData/binary>>.

%% Encryption service
build_encryption_service(Algos) ->
    ServiceType = ?SERVICE_ENCRYPTION,
    SubPacketCount = 3,
    ErrorCode = 0,
    Version = 16#0B200200,

    %% Build algorithm ID list as bytes
    AlgoList = << <<AlgoId:8>> || AlgoId <- Algos >>,
    AlgoListLen = byte_size(AlgoList),

    ServiceData = <<
        %% Version sub-packet (packet_len=4, packet_type=5, version)
        4:16/big, 5:16/big, Version:32/big,
        %% Bytes sub-packet with algorithm IDs (packet_len, packet_type=1, data)
        AlgoListLen:16/big, 1:16/big, AlgoList/binary,
        %% UB1 sub-packet for driver selection (packet_len=1, packet_type=2, value=1)
        1:16/big, 2:16/big, 1:8
    >>,

    <<ServiceType:16/big, SubPacketCount:16/big, ErrorCode:32/big, ServiceData/binary>>.

%% Data integrity service
build_integrity_service(Algos) ->
    ServiceType = ?SERVICE_DATA_INTEGRITY,
    SubPacketCount = 2,
    ErrorCode = 0,
    Version = 16#0B200200,

    %% Build algorithm ID list as bytes
    AlgoList = << <<AlgoId:8>> || AlgoId <- Algos >>,
    AlgoListLen = byte_size(AlgoList),

    ServiceData = <<
        %% Version sub-packet (packet_len=4, packet_type=5, version)
        4:16/big, 5:16/big, Version:32/big,
        %% Bytes sub-packet with algorithm IDs (packet_len, packet_type=1, data)
        AlgoListLen:16/big, 1:16/big, AlgoList/binary
    >>,

    <<ServiceType:16/big, SubPacketCount:16/big, ErrorCode:32/big, ServiceData/binary>>.

%% Parse negotiation response from server
parse_nego_response(<<Magic:32/big, _Length:16/big, _Version:32/big, ServiceCount:16/big, _ErrorFlags:8, Rest/binary>>, State)
        when Magic =:= 16#DEADBEEF ->
    case parse_services(Rest, ServiceCount, #{}, undefined) of
        {ok, Services, DHParams} ->
            %% Check if encryption was negotiated
            case maps:get(encryption, Services, undefined) of
                undefined ->
                    {ok, State, {false, undefined}};
                {AlgoId, _AlgoName} ->
                    StateWithAlgo = State#oraclient{crypto_algo = AlgoId},
                    NeedsDH = case DHParams of
                        undefined -> false;
                        _ -> {true, DHParams}
                    end,
                    {ok, StateWithAlgo, NeedsDH}
            end;
        {error, Reason} ->
            {error, Reason}
    end;
parse_nego_response(_Other, _State) ->
    {error, invalid_response}.

%% Parse individual services from response
parse_services(_Data, 0, Acc, DHParams) ->
    {ok, Acc, DHParams};
parse_services(<<ServiceType:16/big, SubPackets:16/big, ErrorCode:32/big, Rest/binary>>, Remaining, Acc, DHParams) ->
    case ErrorCode of
        0 ->
            case parse_service_data(ServiceType, SubPackets, Rest) of
                {ok, ServiceInfo, RestData, NewDHParams} ->
                    FinalDHParams = case NewDHParams of
                        undefined -> DHParams;
                        _ -> NewDHParams
                    end,
                    NewAcc = case ServiceType of
                        ?SERVICE_ENCRYPTION ->
                            Acc#{encryption => ServiceInfo};
                        ?SERVICE_AUTH -> Acc#{auth => true};
                        ?SERVICE_DATA_INTEGRITY ->
                            Acc#{integrity => true};
                        ?SERVICE_SUPERVISOR -> Acc#{supervisor => true};
                        _ -> Acc
                    end,
                    parse_services(RestData, Remaining - 1, NewAcc, FinalDHParams);
                {error, Reason} ->
                    {error, Reason}
            end;
        _ ->
            {error, {service_error, ServiceType, ErrorCode}}
    end;
parse_services(_Data, _Remaining, _Acc, _DHParams) ->
    {error, parse_error}.

%% Parse service-specific data
parse_service_data(?SERVICE_ENCRYPTION, SubPackets, Data) ->
    %% Read version sub-packet
    case Data of
        <<_PktLen1:16/big, _PktType1:16/big, _Version:32/big, Rest1/binary>> ->
            %% Read algorithm ID sub-packet
            case Rest1 of
                <<_PktLen2:16/big, _PktType2:16/big, AlgoId:8, Rest2/binary>> ->
                    AlgoName = proplists:get_value(AlgoId, ?ALGOS, "Unknown"),
                    RestData = skip_subpackets(SubPackets - 2, Rest2),
                    {ok, {AlgoId, AlgoName}, RestData, undefined};
                _ ->
                    {error, parse_encryption_error}
            end;
        _ ->
            {error, parse_encryption_error}
    end;
parse_service_data(?SERVICE_DATA_INTEGRITY, SubPackets, Data) ->
    %% Check if this is a full DH response (8 sub-packets) or simple response (3 sub-packets)
    case SubPackets of
        8 ->
            %% Server sent DH parameters - parse them
            case parse_dh_params(Data) of
                {ok, DHParams, RestData} ->
                    {ok, true, RestData, DHParams};
                {error, Reason} ->
                    {error, Reason}
            end;
        _ ->
            %% Simple response, just skip
            RestData = skip_subpackets(SubPackets, Data),
            {ok, true, RestData, undefined}
    end;
parse_service_data(_ServiceType, SubPackets, Data) ->
    %% For other services, just skip their data
    RestData = skip_subpackets(SubPackets, Data),
    {ok, true, RestData, undefined}.

%% Parse DH parameters from data integrity service response
parse_dh_params(Data) ->
     try
        %% Skip version sub-packet
        <<_PktLen1:16/big, _PktType1:16/big, _Version:32/big, Rest1/binary>> = Data,

        %% Read algorithm ID sub-packet (this is data integrity algorithm)
        <<_PktLen2:16/big, _PktType2:16/big, IntegrityAlgoId:8, Rest2/binary>> = Rest1,

        %% Read DH gen length sub-packet (in bits)
        <<_PktLen3:16/big, _PktType3:16/big, DHGenLen:16/big, Rest3/binary>> = Rest2,

        %% Read DH prime length sub-packet (in bits)
        <<_PktLen4:16/big, _PktType4:16/big, _DHPrimeLen:16/big, Rest4/binary>> = Rest3,

        %% Calculate expected byte length: (bitLen + 7) / 8
        ByteLen = (DHGenLen + 7) div 8,

        %% Read generator bytes sub-packet (BYTES type 1 has no length prefix, packet length IS -> data size)
        <<GenPktLen:16/big, _GenPktType:16/big, Rest5/binary>> = Rest4,
        <<Gen:GenPktLen/binary, Rest6/binary>> = Rest5,

        %% Read prime bytes sub-packet
        <<PrimePktLen:16/big, _PrimePktType:16/big, Rest7/binary>> = Rest6,
        <<Prime:PrimePktLen/binary, Rest8/binary>> = Rest7,

        %% Read server public key sub-packet
        <<ServerPubKeyPktLen:16/big, _ServerPubKeyPktType:16/big, Rest9/binary>> = Rest8,
        <<ServerPubKey:ServerPubKeyPktLen/binary, Rest10/binary>> = Rest9,

        %% Validate key sizes match expected byte length (go-ora validation)
        ValidationOk = case byte_size(ServerPubKey) =:= ByteLen andalso byte_size(Prime) =:= ByteLen of
            true -> true;
            false -> false
        end,

        case ValidationOk of
            true ->
                %% Read IV sub-packet
                <<IVPktLen:16/big, _IVPktType:16/big, Rest11/binary>> = Rest10,
                <<IV:IVPktLen/binary, RestData/binary>> = Rest11,

                {ok, {IntegrityAlgoId, Gen, Prime, ServerPubKey, IV}, RestData};
            false ->
                {error, key_size_mismatch}
        end
    catch
        _Error:_Reason:_Stacktrace ->
            {error, parse_dh_params_error}
    end.

%% Validate DH parameters before using them
validate_dh_params({_IntegrityAlgoId, Gen, Prime, ServerPubKey, IV}) ->
    %% Validate sizes
    PrimeSize = byte_size(Prime),
    GenSize = byte_size(Gen),
    ServerPubKeySize = byte_size(ServerPubKey),
    IVSize = byte_size(IV),

    %% Check basic size requirements
    case {PrimeSize > 0, GenSize > 0, ServerPubKeySize > 0, IVSize > 0} of
        {true, true, true, true} ->
            %% Check if all key sizes match (except IV which can be different)
            case ServerPubKeySize =:= PrimeSize of
                true -> ok;
                false -> {error, {key_size_mismatch, ServerPubKeySize, PrimeSize}}
            end;
        _ ->
            {error, {invalid_size, PrimeSize, GenSize, ServerPubKeySize, IVSize}}
    end;
validate_dh_params(_) ->
    {error, invalid_format}.

%% Skip N sub-packets
skip_subpackets(0, Data) ->
    Data;
skip_subpackets(N, <<PktLen:16/big, _PktType:16/big, Rest/binary>>) when N > 0 ->
    %% PktLen is just the data size, not including the 4-byte header (Length+Type)
    DataLen = PktLen,
    case Rest of
        <<_SubPktData:DataLen/binary, Remaining/binary>> ->
            skip_subpackets(N - 1, Remaining);
        _ ->
            <<>>
    end;
skip_subpackets(_N, Data) ->
    Data.

%% Initialize encryption based on algorithm ID (matches go-ora encrypt_service.go:73-106)
init_encryption(?ALGO_RC4_40, Key, IV) ->
    jamdb_oracle_network_crypto:new_rc4(Key, IV, 40);
init_encryption(?ALGO_DES56C, Key, _IV) ->
    jamdb_oracle_network_crypto:new_des_cbc(binary:part(Key, 0, min(8, byte_size(Key))), undefined);
init_encryption(?ALGO_RC4_256, Key, IV) ->
    jamdb_oracle_network_crypto:new_rc4(Key, IV, 256);
init_encryption(?ALGO_RC4_56, Key, IV) ->
    jamdb_oracle_network_crypto:new_rc4(Key, IV, 56);
init_encryption(?ALGO_RC4_128, Key, IV) ->
    jamdb_oracle_network_crypto:new_rc4(Key, IV, 128);
init_encryption(?ALGO_3DES112, Key, IV) ->
    jamdb_oracle_network_crypto:new_3des_cbc(binary:part(Key, 0, min(24, byte_size(Key))), IV);
init_encryption(?ALGO_3DES168, Key, IV) ->
    jamdb_oracle_network_crypto:new_3des_cbc(binary:part(Key, 0, min(24, byte_size(Key))), IV);
init_encryption(?ALGO_AES128, Key, _IV) ->
    jamdb_oracle_network_crypto:new_aes_cbc(binary:part(Key, 0, min(16, byte_size(Key))), undefined);
init_encryption(?ALGO_AES192, Key, _IV) ->
    jamdb_oracle_network_crypto:new_aes_cbc(binary:part(Key, 0, min(24, byte_size(Key))), undefined);
init_encryption(?ALGO_AES256, Key, _IV) ->
    jamdb_oracle_network_crypto:new_aes_cbc(binary:part(Key, 0, min(32, byte_size(Key))), undefined);
init_encryption(_AlgoId, _Key, _IV) ->
    {error, unsupported_algorithm}.

%% Activate encryption with session key from advanced negotiation (DH shared key)
%% This is called immediately after advanced negotiation completes, BEFORE authentication
activate_encryption(undefined, State) ->
    {ok, State};
activate_encryption(AlgoId, #oraclient{auth = {SessionKey, ServerIV}, integrity_algo = IntegrityAlgo} = State) when is_binary(SessionKey) ->
    %% Initialize data integrity hash if negotiated
    HashState = case IntegrityAlgo of
        undefined -> undefined;
        1 -> jamdb_oracle_network_hash:new(md5, SessionKey, ServerIV);
        3 -> jamdb_oracle_network_hash:new(sha, SessionKey, ServerIV);
        4 -> jamdb_oracle_network_hash:new(sha512, SessionKey, ServerIV);
        5 -> jamdb_oracle_network_hash:new(sha256, SessionKey, ServerIV);
        6 -> jamdb_oracle_network_hash:new(sha384, SessionKey, ServerIV);
        _ -> undefined
    end,

    %% Initialize encryption (use first 16 bytes of IV for AES)
    IV = binary:part(ServerIV, 0, min(16, byte_size(ServerIV))),
    case init_encryption(AlgoId, SessionKey, IV) of
        {ok, CryptoState} ->
            {ok, State#oraclient{crypto = CryptoState, hash_state = HashState}};
        {error, Reason} ->
            {error, Reason}
    end;
activate_encryption(AlgoId, #oraclient{auth = SessionKey} = State) when is_binary(SessionKey) ->
    %% Fallback for old code path with just session key (no IV)
    %% Use zero IV as fallback
    IV = <<0:128>>,

    case init_encryption(AlgoId, SessionKey, IV) of
        {ok, CryptoState} ->
            {ok, State#oraclient{crypto = CryptoState}};
        {error, Reason} ->
            {error, Reason}
    end;
activate_encryption(_AlgoId, State) ->
    {ok, State}.
