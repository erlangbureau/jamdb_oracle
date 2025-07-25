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
    {read_timeout, non_neg_integer()} |
    {autocommit, non_neg_integer()} |
    {fetch, non_neg_integer()} |
    {sdu, non_neg_integer()} |
    {role, non_neg_integer()} |
    {prelim, non_neg_integer()} |
    {newpassword, string()} |
    {proxy_user, string()} |
    {description, string()} |
    {app_name, string()}.

-record(oraclient, {
    socket = undefined,
    conn_state = disconnected :: disconnected | connected | auth_negotiate,
    auto = 1 :: 1 | 0,
    type = select  :: select  | block | change | return | fetch,
    auth,
    charset,
    fetch,
    sdu,
    server,
    timeouts,
    cursors,
    defcols,
    params = [],
    env = [],
    passwd,
    req,
    seq
}).

-record(logon, {
    user,
    password,
    newpassword,
    type,
    auth,
    bits,
    salt,
    der_salt,
    key,
    der_key,
    speedy_key
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
    {us7ascii, 1},
    {we8iso8859p1, 31},
    {ee8iso8859p2, 32},
    {nee8iso8859p4, 34},
    {cl8iso8859p5, 35},
    {ar8iso8859p6, 36},
    {el8iso8859p7, 37},
    {iw8iso8859p8, 38},
    {we8iso8859p9, 39},
    {ne8iso8859p10, 40},
    {th8tisascii, 41},
    {vn8mswin1258, 45},
    {we8iso8859p15, 46},
    {blt8iso8859p13, 47},
    {ee8mswin1250, 170},
    {cl8mswin1251, 171},
    {el8mswin1253, 174},
    {iw8mswin1255, 175},
    {tr8mswin1254, 177},
    {we8mswin1252, 178},
    {blt8mswin1257, 179},
    {ar8mswin1256, 560},
    {ja16euc, 830},
    {ja16sjis, 832},
    {ja16euctilde, 837},
    {ja16sjistilde, 838},
    {ko16mswin949, 846},
    {zhs16gbk, 852},
    {zht32euc, 860},
    {zht16big5, 865},
    {zht16mswin950, 867},
    {zht16hkscs, 868},
    {al32utf8, 873},
    {al16utf16, 2000}
]).

-define(REGION, [
    "Africa",
    "America",
    "Asia",
    "Atlantic",
    "Australia",
    "Brazil",
    "Canada",
    "Europe",
    "Pacific",
    "US",
    "Etc"
]).

-define(ZONEIDMAP, [
    {44, {1, "Cairo"}},
    {61, {1, "Casablanca"}},
    {80, {1, "Harare"}},
    {66, {1, "Lagos"}},
    {31, {1, "Luanda"}},
    {55, {1, "Monrovia"}},
    {53, {1, "Nairobi"}},
    {64, {1, "Windhoek"}},

    {186, {2, "Araguaina"}},
    {175, {2, "Buenos_Aires"}},
    {200, {2, "Asuncion"}},
    {195, {2, "Bogota"}},
    {205, {2, "Caracas"}},
    {101, {2, "Chicago"}},
    {142, {2, "Chihuahua"}},
    {189, {2, "Cuiaba"}},
    {102, {2, "Denver"}},
    {116, {2, "Detroit"}},
    {185, {2, "Fortaleza"}},
    {207, {2, "Godthab"}},
    {159, {2, "Guatemala"}},
    {120, {2, "Halifax"}},
    {201, {2, "Lima"}},
    {103, {2, "Los_Angeles"}},
    {192, {2, "Manaus"}},
    {87, {2, "Matamoros"}},
    {141, {2, "Mexico_City"}},
    {227, {2, "Monterrey"}},
    {204, {2, "Montevideo"}},
    {100, {2, "New_York"}},
    {109, {2, "Phoenix"}},
    {194, {2, "Santiago"}},
    {188, {2, "Sao_Paulo"}},
    {145, {2, "Tijuana"}},
    {220, {2, "Toronto"}},

    {268, {3, "Amman"}},
    {297, {3, "Ashgabat"}},
    {265, {3, "Baghdad"}},
    {242, {3, "Baku"}},
    {296, {3, "Bangkok"}},
    {277, {3, "Beirut"}},
    {260, {3, "Calcutta"}},
    {294, {3, "Damascus"}},
    {756, {3, "Dhaka"}},
    {254, {3, "Hong_Kong"}},
    {307, {3, "Irkutsk"}},
    {261, {3, "Jakarta"}},
    {266, {3, "Jerusalem"}},
    {240, {3, "Kabul"}},
    {284, {3, "Karachi"}},
    {797, {3, "Kathmandu"}},
    {772, {3, "Kolkata"}},
    {306, {3, "Krasnoyarsk"}},
    {310, {3, "Magadan"}},
    {286, {3, "Manila"}},
    {283, {3, "Muscat"}},
    {305, {3, "Novosibirsk"}},
    {247, {3, "Rangoon"}},
    {288, {3, "Riyadh"}},
    {273, {3, "Seoul"}},
    {250, {3, "Shanghai"}},
    {292, {3, "Singapore"}},
    {255, {3, "Taipei"}},
    {264, {3, "Tehran"}},
    {267, {3, "Tokyo"}},
    {281, {3, "Ulaanbaatar"}},
    {309, {3, "Vladivostok"}},
    {308, {3, "Yakutsk"}},
    {241, {3, "Yerevan"}},

    {336, {4, "Azores"}},
    {339, {4, "Cape_Verde"}},

    {349, {5, "Adelaide"}},
    {347, {5, "Brisbane"}},
    {345, {5, "Darwin"}},
    {356, {5, "Eucla"}},
    {350, {5, "Hobart"}},
    {354, {5, "Lord_Howe"}},
    {346, {5, "Perth"}},
    {352, {5, "Sydney"}},

    {695, {6, "DeNoronha"}},
    {700, {6, "East"}},

    {630, {7, "Newfoundland"}},
    {1151, {7, "Saskatchewan"}},

    {396, {8, "Amsterdam"}},
    {385, {8, "Athens"}},
    {383, {8, "Berlin"}},
    {371, {8, "Dublin"}},
    {381, {8, "Helsinki"}},
    {401, {8, "Kaliningrad"}},
    {408, {8, "Kiev"}},
    {369, {8, "London"}},
    {404, {8, "Madrid"}},
    {402, {8, "Moscow"}},
    {382, {8, "Paris"}},
    {378, {8, "Prague"}},
    {387, {8, "Rome"}},
    {1436, {8, "Sarajevo"}},
    {405, {8, "Stockholm"}},

    {479, {9, "Apia"}},
    {471, {9, "Auckland"}},
    {472, {9, "Chatham"}},
    {454, {9, "Fiji"}},
    {458, {9, "Guam"}},
    {450, {9, "Honolulu"}},
    {461, {9, "Kiritimati"}},
    {456, {9, "Marquesas"}},
    {1502, {9, "Samoa"}},
    {483, {9, "Tongatapu"}},
    {487, {9, "Wake"}},

    {618, {10, "Alaska"}},
    {613, {10, "Central"}},
    {1135, {10, "East-Indiana"}},
    {612, {10, "Eastern"}},
    {615, {10, "Pacific"}},

    {28, {11, "UTC"}}	
]).

-define(TNS_HRL, "11.2.0.3").

-endif.
