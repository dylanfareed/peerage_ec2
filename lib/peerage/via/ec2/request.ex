defmodule Peerage.Via.Ec2.Request do
  #http://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
  def sign(url, region \\ "us-east-1") do
    service = "ec2"
    access_key = System.get_env("AWS_ACCESS_KEY_ID")
    secret_key = System.get_env("AWS_SECRET_ACCESS_KEY")
    request_time = DateTime.utc_now |> DateTime.to_naive
    payload = ""

    uri = URI.parse(url)
    region = String.downcase(region)

    headers = %{"host" => uri.host}

    amz_date = format_time(request_time)
    date = format_date(request_time)

    scope = "#{date}/#{region}/#{service}/aws4_request"

    params = case uri.query do
               nil ->
                 Map.new
               _ ->
                 URI.decode_query(uri.query)
             end

    params =
      params
      |> Map.put("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
      |> Map.put("X-Amz-Credential", "#{access_key}/#{scope}")
      |> Map.put("X-Amz-Date", amz_date)
      |> Map.put("X-Amz-Expires", "86400")
      |> Map.put("X-Amz-SignedHeaders", "#{Map.keys(headers) |> Enum.join(";")}")

    hashed_payload = hash_sha256(payload)

    string_to_sign =
      uri.path
      |> build_canonical_request(params, headers, hashed_payload)
      |> build_string_to_sign(amz_date, scope)

    signature =
      secret_key
      |> build_signing_key(date, region, service)
      |> build_signature(string_to_sign)

    query_string =
      params
      |> Map.put("X-Amz-Signature", signature)
      |> URI.encode_query
      |> String.replace("+", "%20")

    "#{uri.scheme}://#{uri.authority}#{uri.path || "/"}?#{query_string}"
  end

  defp build_canonical_request(path, params, headers, hashed_payload) do
    query_params = URI.encode_query(params) |> String.replace("+", "%20")

    header_params = Enum.map(headers, fn({key, value}) -> "#{String.downcase(key)}:#{String.trim(value)}"  end)
    |> Enum.sort(&(&1 < &2))
    |> Enum.join("\n")

    signed_header_params = Enum.map(headers, fn({key, _}) -> String.downcase(key)  end)
    |> Enum.sort(&(&1 < &2))
    |> Enum.join(";")

    encoded_path =
      path
      |> String.split("/")
      |> Enum.map(fn (segment) -> URI.encode_www_form(segment) end)
      |> Enum.join("/")

    "GET\n#{encoded_path}\n#{query_params}\n#{header_params}\n\n#{signed_header_params}\n#{hashed_payload}"
  end

  defp build_string_to_sign(canonical_request, timestamp, scope) do
    hashed_canonical_request = hash_sha256(canonical_request)
    "AWS4-HMAC-SHA256\n#{timestamp}\n#{scope}\n#{hashed_canonical_request}"
  end

  defp build_signing_key(secret_key, date, region, service) do
    "AWS4#{secret_key}"
    |> hmac_sha256(date)
    |> hmac_sha256(region)
    |> hmac_sha256(service)
    |> hmac_sha256("aws4_request")
  end

  defp build_signature(signing_key, string_to_sign) do
    signing_key
    |> hmac_sha256(string_to_sign)
    |> bytes_to_string
  end

  defp hash_sha256(data) do
    :sha256
    |> :crypto.hash(data)
    |> bytes_to_string
  end

  defp hmac_sha256(key, data), do: :crypto.hmac(:sha256, key, data)

  defp bytes_to_string(bytes), do: Base.encode16(bytes, case: :lower)

  defp format_time(time) do
    formatted_time = time
    |> NaiveDateTime.to_iso8601
    |> String.split(".")
    |> List.first
    |> String.replace("-", "")
    |> String.replace(":", "")
    formatted_time <> "Z"
  end

  defp format_date(date) do
    date
    |> NaiveDateTime.to_date
    |> Date.to_iso8601
    |> String.replace("-", "")
  end
end
