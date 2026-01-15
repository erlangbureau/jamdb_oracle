#!/usr/bin/env escript
%% TNS packet decoder for Oracle disconnect analysis
%% Usage: escript decode_disconnect.escript <binary_data>

main([BinaryData]) ->
    %% Parse disconnect data
    case catch binary_to_list(BinaryData) of
        List when is_list(List) ->
            Data = list_to_binary(List),
            analyze_disconnect(Data);
        {'EXIT', _} ->
            io:format("Invalid binary format~n"),
            halt(1)
    end;
main(_) ->
    io:format("Usage: escript decode_disconnect.escript <binary_data>~n"),
    halt(1).

analyze_disconnect(<<Code:8, ErrNum:8, Reason:8, Flags:8, _Rest/binary>>) ->
    io:format("~n=== TNS Disconnect Analysis ===~n", []),
    io:format("Return Code: ~p (0xEOS = End of Session)~n", [Code]),
    io:format("Error Number: ~p~n", [ErrNum]),
    io:format("Reason: ~p~n", [Reason]),
    io:format("Flags: ~p~n", [Flags]),

    %% Known reasons
    ReasonMap = #{
        1 => "Operation completed successfully",
        2 => "Function not supported",
        5 => "Invalid argument",
        10 => "Authentication failure",
        22 => "Data integrity check failed",
        27 => "Encryption type not supported",
        28 => "Encryption required",
        29 => "Encryption type mismatch",
        30 => "Encryption needed",
        31 => "Encryption algorithm not supported",
        54 => "Session timed out",
        123 => "Session killed"
    },

    io:format("~nInterpretation: ~s~n~n", [maps:get(Reason, ReasonMap, "Unknown reason")]),

    %% Check for encryption-related codes
    case lists:member(Reason, [27, 28, 29, 30, 31]) of
        true ->
            io:format("!!! ENCRYPTION ISSUE DETECTED !!!~n~n", []),
            io:format("Oracle is rejecting the connection due to encryption settings.~n", []),
            io:format("This database likely requires:~n"),
            io:format("   - Different encryption algorithm~n"),
            io:format("  - SSL/TLS instead of native encryption~n"),
            io:format("  - Specific encryption type (AES256 only, etc)~n"),
            io:format("~nSOLUTION: Try with ssl: true and port: 2481~n~n")
    end;

    io:format("~nFlag Analysis:~n", []),
    io:format("  Acfl0/1 bits: ~p~n", [<<Flags:6,7>>]),
    io:format("  Acfl2/3/4 bits: ~p~n", [<<Flags:4,5,6,7>>]).
