defmodule ExOauth2Provider.Authorization.Utils.Response do
  @moduledoc false

  alias ExOauth2Provider.{RedirectURI, Scopes, Utils}
  alias Ecto.Schema

  @type code_response :: %{code: binary()}
  @type access_token_response :: %{access_token: binary(), expires_in: integer(), scopes: binary()}

  @doc false
  @spec error_response(map()) :: {:error, map(), integer()} |
                                 {:redirect, binary()} |
                                 {:native_redirect, code_response} |
                                 {:native_redirect, access_token_response()}
  def error_response(%{error: error} = params),
    do: build_response(params, error)

  @doc false
  @spec preauthorize_response(map()) :: {:ok, Schema.t(), [binary()]} |
                                        {:error, map(), integer()} |
                                        {:redirect, binary()} |
                                        {:native_redirect, code_response} |
                                        {:native_redirect, access_token_response}
  def preauthorize_response(%{grant: grant} = params), do: build_response(params, %{code: grant.token})
  def preauthorize_response(%{access_token: access_token} = params), do: build_response(params, access_token_response(access_token))
  def preauthorize_response(%{error: error} = params), do: build_response(params, error)

  def preauthorize_response(%{client: client, request: %{"scope" => scopes}}),
    do: {:ok, client, Scopes.to_list(scopes)}

  @doc false
  @spec authorize_response(map()) :: {:ok, Schema.t(), [binary()]} |
                                     {:error, map(), integer()} |
                                     {:redirect, binary()} |
                                     {:native_redirect, code_response} |
                                     {:native_redirect, access_token_response}
  def authorize_response(%{grant: grant} = params), do: build_response(params, %{code: grant.token})
  def authorize_response(%{access_token: access_token} = params), do: build_response(params, access_token_response(access_token))
  def authorize_response(%{error: error} = params), do: build_response(params, error)

  @doc false
  @spec deny_response(map()) :: {:error, map(), integer()} |
                                {:redirect, binary()} |
                                {:native_redirect, code_response} |
                                {:native_redirect, access_token_response}
  def deny_response(%{error: error} = params), do: build_response(params, error)

  defp build_response(%{request: request} = params, payload) do
    payload = add_state(payload, request)

    case can_redirect?(params) do
      true -> build_redirect_response(params, payload)
      _ -> build_standard_response(params, payload)
    end
  end

  defp access_token_response(access_token) do
    %{
      access_token: access_token.token,
      expires_in: access_token.expires_in,
      scopes: access_token.scopes
    }
  end

  defp add_state(payload, request) do
    case request["state"] do
      nil ->
        payload

      state ->
        %{"state" => state}
        |> Map.merge(payload)
        |> Utils.remove_empty_values()
    end
  end

  defp build_redirect_response(%{request: %{"redirect_uri" => redirect_uri}}, payload) do
    case RedirectURI.native_redirect_uri?(redirect_uri) do
      true -> {:native_redirect, payload}
      _ -> {:redirect, RedirectURI.uri_with_query(redirect_uri, payload)}
    end
  end

  defp build_standard_response(%{grant: _}, payload) do
    {:ok, payload}
  end

  defp build_standard_response(%{error: error, error_http_status: error_http_status}, _) do
    {:error, error, error_http_status}
  end

  # For DB errors
  defp build_standard_response(%{error: error}, _) do
    {:error, error, :bad_request}
  end

  defp can_redirect?(%{error: %{error: :invalid_redirect_uri}}), do: false
  defp can_redirect?(%{error: %{error: :invalid_client}}), do: false

  defp can_redirect?(%{error: %{error: _error}, request: %{"redirect_uri" => redirect_uri}}),
    do: !RedirectURI.native_redirect_uri?(redirect_uri)

  defp can_redirect?(%{error: _}), do: false
  defp can_redirect?(%{request: %{}}), do: true
end
