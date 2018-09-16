-ifndef(TNS_HRL).

-include("TNS.hrl").
-include("jamdb_oracle_defaults.hrl").

-define(ENCODER, jamdb_oracle_tns_encoder).
-define(DECODER, jamdb_oracle_tns_decoder).

-type env() ::
    {host, string()} |
    {port, non_neg_integer()} |
    {user, string()} |
    {password, string()} |
    {sid, string()} |
    {service_name, string()} |
    {ssl, list()} |
    {socket_options, list()} |
    {timeout, non_neg_integer()} |
    {autocommit, non_neg_integer()} |
    {fetch, non_neg_integer()} |
    {role, non_neg_integer()} |
    {prelim, non_neg_integer()} |
    {app_name, string()}.

-record(oraclient, {
    socket = undefined,
    conn_state = disconnected :: disconnected | connected | auth_negotiate,
    auto = 1 :: 1 | 0,
    type = select  :: select  | block | change | return | fetch,
    timeout,
    auth,
    fetch,
    sdu,
    server,
    cursors,
    defcols,
    params = [],
    env = [],
    req,
    seq
}).

-record(logon, {
    user,
    password,
    auth,
    bits,
    salt,
    der_salt,
    key,
    der_key
}).

-record(format, {
    column_name = <<>>,
    param = in :: in | out,
    data_type,
    data_length,
    data_scale,
    charset
}).

-define(IS_FIXED_TYPE(DataType),
    ?IS_NUMBER_TYPE(DataType);
    ?IS_BINARY_TYPE(DataType);
    ?IS_DATE_TYPE(DataType);
    ?IS_INTERVAL_TYPE(DataType)
).

-define(IS_NULL_TYPE(DataType),
    DataType =/= ?TNS_TYPE_LONG,
    DataType =/= ?TNS_TYPE_LONGRAW
).

-define(IS_CHAR_TYPE(DataType),
    DataType =:= ?TNS_TYPE_CHAR;
    DataType =:= ?TNS_TYPE_VARCHAR;
    DataType =:= ?TNS_TYPE_VCS
).

-define(IS_RAW_TYPE(DataType),
    DataType =:= ?TNS_TYPE_RAW;
    DataType =:= ?TNS_TYPE_VBI
).

-define(IS_NUMBER_TYPE(DataType),
    DataType =:= ?TNS_TYPE_NUMBER;
    DataType =:= ?TNS_TYPE_FLOAT;
    DataType =:= ?TNS_TYPE_VARNUM
).

-define(IS_BINARY_TYPE(DataType),
    DataType =:= ?TNS_TYPE_BFLOAT;
    DataType =:= ?TNS_TYPE_BDOUBLE
).

-define(IS_ROWID_TYPE(DataType),
    DataType =:= ?TNS_TYPE_ROWID;
    DataType =:= ?TNS_TYPE_RID
).

-define(IS_LOB_TYPE(DataType),
    DataType =:= ?TNS_TYPE_CLOB;
    DataType =:= ?TNS_TYPE_BLOB
).

-define(IS_LONG_TYPE(DataType),
    DataType =:= ?TNS_TYPE_LONG;
    DataType =:= ?TNS_TYPE_LONGRAW
).

-define(IS_INTERVAL_TYPE(DataType),
    DataType =:= ?TNS_TYPE_INTERVALYM;
    DataType =:= ?TNS_TYPE_INTERVALDS
).

-define(IS_DATE_TYPE(DataType),
    DataType =:= ?TNS_TYPE_DATE;
    DataType =:= ?TNS_TYPE_TIMESTAMP;
    DataType =:= ?TNS_TYPE_TIMESTAMPTZ;
    DataType =:= ?TNS_TYPE_TIMESTAMPLTZ
).

-define(ISO_LATIN_1_CHARSET, 31).
-define(UTF8_CHARSET, 871).
-define(AL32UTF8_CHARSET, 873).
-define(AL16UTF16_CHARSET, 2000).

-define(CHARSET, [
    {we8iso8859p1, 31},
    {ee8iso8859p2, 32},
    {cl8iso8859p5, 35},
    {ee8mswin1250, 170},
    {cl8mswin1251, 171},
    {we8mswin1252, 178},
    {ja16euc, 830},
    {zhs16gbk, 852},
    {zht16big5, 865},
    {zht16mswin950, 867},
    {al32utf8, 873},
    {al16utf16, 2000}
]).

-define(ZONEIDMAP, [
    {100, "America/New_York"},
    {101, "America/Chicago"},
    {102, "America/Denver"},
    {103, "America/Los_Angeles"},
    {250, "Asia/Shanghai"},
    {254, "Asia/Hong_Kong"},
    {267, "Asia/Tokyo"},
    {296, "Asia/Bangkok"},
    {369, "Europe/London"},
    {402, "Europe/Moscow"},
    {405, "Europe/Stockholm"},
    {408, "Europe/Kiev"}
]).

-define(TNS_HRL, "11.2.0.3").

-endif.
