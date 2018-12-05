defmodule ExOauth2Provider.Authorization.ImplicitTest do
  use ExOauth2Provider.TestCase

  alias ExOauth2Provider.Test.{Fixtures, QueryHelpers}
  alias ExOauth2Provider.{Authorization, Scopes, OauthAccessTokens.OauthAccessToken}

  @client_id "Jf5rM8hQBc"
  @valid_request %{
    "client_id" => @client_id,
    "response_type" => "token",
    "scope" => "app:read app:write"
  }
  @invalid_request %{
    error: :invalid_request,
    error_description:
      "The request is missing a required parameter, includes an unsupported parameter value, or is otherwise malformed."
  }
  @invalid_client %{
    error: :invalid_client,
    error_description:
      "Client authentication failed due to unknown client, no client authentication included, or unsupported authentication method."
  }
  @invalid_scope %{
    error: :invalid_scope,
    error_description: "The requested scope is invalid, unknown, or malformed."
  }
  @invalid_redirect_uri %{
    error: :invalid_redirect_uri,
    error_description: "The redirect uri included is not valid."
  }
  @access_denied %{
    error: :access_denied,
    error_description: "The resource owner or authorization server denied the request."
  }

  setup do
    resource_owner = Fixtures.resource_owner()

    application =
      Fixtures.application(Fixtures.resource_owner(), %{
        uid: @client_id,
        scopes: "app:read app:write"
      })

    {:ok, %{resource_owner: resource_owner, application: application}}
  end

  test "#preauthorize/2 error when no resource owner" do
    assert {:error, error, :bad_request} = Authorization.preauthorize(nil, @valid_request)
    assert error == @invalid_request
  end

  test "#preauthorize/2 error when no client_id", %{resource_owner: resource_owner} do
    assert {:error, error, :bad_request} =
             Authorization.preauthorize(resource_owner, Map.delete(@valid_request, "client_id"))

    assert error == @invalid_request
  end

  test "#preauthorize/2 error when invalid client", %{resource_owner: resource_owner} do
    assert {:error, error, :unprocessable_entity} =
             Authorization.preauthorize(
               resource_owner,
               Map.merge(@valid_request, %{"client_id" => "invalid"})
             )

    assert error == @invalid_client
  end

  test "#preauthorize/2", %{resource_owner: resource_owner, application: application} do
    assert Authorization.preauthorize(resource_owner, @valid_request) ==
             {:ok, application, Scopes.to_list(@valid_request["scope"])}
  end

  test "#preauthorize/2 when previous access token with different application scopes", %{
    resource_owner: resource_owner,
    application: application
  } do
    access_token =
      Fixtures.access_token(resource_owner, %{application: application, scopes: "app:read"})

    assert Authorization.preauthorize(resource_owner, @valid_request) ==
             {:ok, application, Scopes.to_list(@valid_request["scope"])}

    QueryHelpers.change!(access_token, scopes: "app:read app:write")

    request = Map.merge(@valid_request, %{"scope" => "app:read"})

    assert Authorization.preauthorize(resource_owner, request) ==
             {:ok, application, Scopes.to_list(request["scope"])}
  end

  test "#preauthorize/2 with limited scope", %{
    resource_owner: resource_owner,
    application: application
  } do
    request = Map.merge(@valid_request, %{"scope" => "app:read"})
    assert Authorization.preauthorize(resource_owner, request) == {:ok, application, ["app:read"]}
  end

  test "#preauthorize/2 error when invalid scope", %{resource_owner: resource_owner} do
    request = Map.merge(@valid_request, %{"scope" => "app:invalid"})

    assert {:error, error, :unprocessable_entity} =
             Authorization.preauthorize(resource_owner, request)

    assert error == @invalid_scope
  end

  describe "#preauthorize/2 when application has no scope" do
    setup %{resource_owner: resource_owner, application: application} do
      application = QueryHelpers.change!(application, scopes: "")

      %{resource_owner: resource_owner, application: application}
    end

    test "with limited server scope", %{resource_owner: resource_owner, application: application} do
      request = Map.merge(@valid_request, %{"scope" => "read"})
      assert {:ok, application, ["read"]} == Authorization.preauthorize(resource_owner, request)
    end

    test "error when invalid server scope", %{resource_owner: resource_owner} do
      assert {:error, error, :unprocessable_entity} =
               Authorization.preauthorize(
                 resource_owner,
                 Map.merge(@valid_request, %{"scope" => "invalid"})
               )

      assert error == @invalid_scope
    end
  end

  test "#preauthorize/2 when previous access token with same scopes", %{
    resource_owner: resource_owner,
    application: application
  } do
    Fixtures.access_token(resource_owner, %{
      application: application,
      expires_in: 600,
      scopes: @valid_request["scope"]
    })

    assert {:native_redirect, response} = Authorization.preauthorize(resource_owner, @valid_request)

    assert response[:access_token] == QueryHelpers.get_latest_inserted(OauthAccessToken).token
    assert response[:expires_in] == 600
    assert response[:scopes] == @valid_request["scope"]
  end

  test "#preauthorize/2 without prompting the resource owner", %{
    resource_owner: resource_owner
  } do
    request = @valid_request |> Map.put("prompt", "false")

    assert {:native_redirect, %{access_token: token}} =
             Authorization.preauthorize(resource_owner, request)

    assert token == QueryHelpers.get_latest_inserted(OauthAccessToken).token
  end

  test "#authorize/2 rejects when no resource owner" do
    assert {:error, error, :bad_request} = Authorization.authorize(nil, @valid_request)
    assert error == @invalid_request
  end

  test "#authorize/2 error when invalid client", %{resource_owner: resource_owner} do
    assert {:error, error, :unprocessable_entity} =
             Authorization.authorize(
               resource_owner,
               Map.merge(@valid_request, %{"client_id" => "invalid"})
             )

    assert error == @invalid_client
  end

  test "#authorize/2 error when no client_id", %{resource_owner: resource_owner} do
    assert {:error, error, :bad_request} =
             Authorization.authorize(resource_owner, Map.delete(@valid_request, "client_id"))

    assert error == @invalid_request
  end

  test "#authorize/2 error when invalid scope", %{resource_owner: resource_owner} do
    request = Map.merge(@valid_request, %{"scope" => "app:read app:profile"})

    assert {:error, error, :unprocessable_entity} =
             Authorization.authorize(resource_owner, request)

    assert error == @invalid_scope
  end

  describe "#authorize/2 when application has no scope" do
    setup %{resource_owner: resource_owner, application: application} do
      application = QueryHelpers.change!(application, scopes: "")

      %{resource_owner: resource_owner, application: application}
    end

    test "error when invalid server scope", %{resource_owner: resource_owner} do
      request = Map.merge(@valid_request, %{"scope" => "public profile"})

      assert {:error, error, :unprocessable_entity} =
               Authorization.authorize(resource_owner, request)

      assert error == @invalid_scope
    end

    test "generates access token", %{resource_owner: resource_owner} do
      request = Map.merge(@valid_request, %{"scope" => "public"})

      assert {:native_redirect, %{access_token: token}} =
               Authorization.authorize(resource_owner, request)

      assert QueryHelpers.get_by(OauthAccessToken, token: token).resource_owner_id ==
               resource_owner.id
    end
  end

  test "#authorize/2 error when invalid redirect uri", %{resource_owner: resource_owner} do
    assert {:error, error, :unprocessable_entity} =
             Authorization.authorize(
               resource_owner,
               Map.merge(@valid_request, %{"redirect_uri" => "/invalid/path"})
             )

    assert error == @invalid_redirect_uri
  end

  test "#authorize/2 generates access token", %{resource_owner: resource_owner} do
    assert {:native_redirect, %{access_token: token}} =
             Authorization.authorize(resource_owner, @valid_request)

    assert access_token = QueryHelpers.get_by(OauthAccessToken, token: token)
    assert access_token.resource_owner_id == resource_owner.id
    assert access_token.expires_in == ExOauth2Provider.Config.access_token_expires_in()
    assert access_token.scopes == @valid_request["scope"]
  end

  test "#authorize/2 generates acccess token with redirect uri", %{
    resource_owner: resource_owner,
    application: application
  } do
    QueryHelpers.change!(
      application,
      redirect_uri: "#{application.redirect_uri}\nhttps://example.com/path"
    )

    params =
      Map.merge(@valid_request, %{
        "redirect_uri" => "https://example.com/path?param=1",
        "state" => 40_612
      })

    assert {:redirect, redirect_uri} = Authorization.authorize(resource_owner, params)
    token = QueryHelpers.get_latest_inserted(OauthAccessToken).token
    assert redirect_uri == "https://example.com/path#access_token=#{token}&expires_in=7200&scopes=app%3Aread+app%3Awrite&param=1&state=40612"
  end

  test "#deny/2 error when no resource owner" do
    assert {:error, _, _} = Authorization.deny(nil, @valid_request)
  end

  test "#deny/2 error when invalid client", %{resource_owner: resource_owner} do
    assert {:error, error, :unprocessable_entity} =
             Authorization.deny(
               resource_owner,
               Map.merge(@valid_request, %{"client_id" => "invalid"})
             )

    assert error == @invalid_client
  end

  test "#deny/2 error when no client_id", %{resource_owner: resource_owner} do
    assert {:error, error, :bad_request} =
             Authorization.deny(resource_owner, Map.delete(@valid_request, "client_id"))

    assert error == @invalid_request
  end

  test "#deny/2", %{resource_owner: resource_owner} do
    assert {:error, error, :unauthorized} = Authorization.deny(resource_owner, @valid_request)
    assert error == @access_denied
  end

  test "#deny/2 with redirection uri", %{application: application, resource_owner: resource_owner} do
    QueryHelpers.change!(
      application,
      redirect_uri: "#{application.redirect_uri}\nhttps://example.com/path"
    )

    params =
      Map.merge(@valid_request, %{
        "redirect_uri" => "https://example.com/path?param=1",
        "state" => 40_612
      })

    assert {:redirect,
            "https://example.com/path?error=access_denied&error_description=The+resource+owner+or+authorization+server+denied+the+request.&param=1&state=40612"} =
             Authorization.deny(resource_owner, params)
  end
end
