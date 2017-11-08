defmodule Peerage.Via.Ec2 do
  @moduledoc """
  A Peerage provider for easy clustering on AWS EC2 and Elastic Beanstalk.
  """
  import SweetXml, only: [sigil_x: 2, xpath: 2, xpath: 3]

  alias Peerage.Via.Ec2.Utils

  @doc """
  Periodically polls the metadata and EC2 API's for other nodes in the same "cluster."
  """
  def poll() do
    fetch_instance_id()
    |> fetch_cluster_name()
    |> fetch_running_services()
    |> format_services_list()
  end

  defp fetch_instance_id() do
    # NOTE: EC2 provides an instance metadata API endpoint. We'll perform a request to determine
    # the ID of the running instance.
    #
    # AWS Documentation: http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html
    metadata_api = 'http://169.254.169.254/latest/meta-data/instance-id'
    case :httpc.request(metadata_api) do
      {:ok, {{_, 200, _}, _headers, body}} -> to_string(body)
      _ -> :error
    end
  end

  defp fetch_cluster_name(:error), do: :error
  defp fetch_cluster_name(instance_id) do
    request_uri =
      %{}
      |> Map.put("Filter.1.Name", "instance-id")
      |> Map.put("Filter.1.Value.1", instance_id)
      |> describe_endpoint()
      |> Utils.sign()
      |> to_charlist

    case :httpc.request(request_uri) do
      {:ok, {{_, 200, _}, _headers, body}} ->
        body
        |> xpath(~x"//tagSet/item[key='#{tag_name(:cluster)}']/value/text()")
        |> to_string
      _ -> :error
    end
  end

  defp fetch_running_services(:error), do: :error
  defp fetch_running_services(cluster_name) do
    # NOTE: An InstanceState code of 16 represents a running EC2 service.
    #
    # AWS Documentation: http://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_InstanceState.html
    request_uri =
      %{}
      |> Map.put("Filter.1.Name", "instance-state-code")
      |> Map.put("Filter.1.Value.1", "16")
      |> Map.put("Filter.2.Name", "tag:#{tag_name(:cluster)}")
      |> Map.put("Filter.2.Value.1", cluster_name)
      |> describe_endpoint()
      |> Utils.sign()
      |> to_charlist

    case :httpc.request(request_uri) do
      {:ok, {{_, 200, _}, _headers, body}} ->
        xpath(body, ~x"//instancesSet/item"l, host: ~x"./privateIpAddress/text()",
                                              name: ~x"./tagSet/item[key='service']/value/text()")
      _ -> :error
    end
  end

  defp format_services_list(:error), do: []
  defp format_services_list(services) do
    Enum.map(services, fn(service) ->
      String.to_atom("#{service.name}@" <> to_string(service.host))
    end)
  end

  defp describe_endpoint(filters) do
    query_string =
      filters
      |> Map.put("Action", "DescribeInstances")
      |> Map.put("Version", "2016-11-15")
      |> URI.encode_query
    "https://ec2.amazonaws.com/?" <> query_string
  end

  defp tag_name(key), do: Application.fetch_env!(:peerage_ec2, :tags)[key]
end
