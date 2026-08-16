defmodule JamdbOracleTnsDecoderTest do
  use ExUnit.Case, async: true

  @tti_rpa 8
  @tti_status 9

  test "return parameters skip chunked keyword values" do
    data = return_parameters(<<0>>, chunked_field())
    assert_decoded(data)
  end

  test "return parameters skip chunked keywords" do
    data = return_parameters(chunked_field(), <<0>>)
    assert_decoded(data)
  end

  defp chunked_field do
    first_chunk = :binary.copy(<<0xAA>>, 64)
    encoded_value = <<254, 64, first_chunk::binary, 1, 0xBB, 0>>
    <<1, 65, encoded_value::binary>>
  end

  defp return_parameters(keyword, value) do
    <<
      @tti_rpa,
      # no array parameters
      0,
      # no text value
      0,
      # one keyword/value pair
      1,
      1,
      keyword::binary,
      value::binary,
      # keyword number
      0,
      # no registration info
      0,
      @tti_status
    >>
  end

  defp assert_decoded(data) do
    accumulator = {0, [], []}

    assert {:ok, ^accumulator} = :jamdb_oracle_tns_decoder.decode_two_task(data, accumulator)
  end
end
