-record(format, {
    owner_name,
    column_name = <<>>,
    param = in :: in | out,
    data_type,
    data_length,
    scale,
    locale
}).
