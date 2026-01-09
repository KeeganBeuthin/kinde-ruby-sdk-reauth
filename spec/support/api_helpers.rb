# frozen_string_literal: true

# Provides HTTP stubbing utilities for API tests.
# Encapsulates WebMock patterns for consistent API mocking.
module ApiHelpers
  extend self

  DEFAULT_DOMAIN = 'https://test.kinde.com'

  # Stubs the JWKS endpoint for token validation
  #
  # @param domain [String] The Kinde domain
  # @param jwks [Hash] The JWKS to return (defaults to test JWKS)
  def stub_jwks_endpoint(domain: DEFAULT_DOMAIN, jwks: nil)
    jwks ||= JwtHelpers.jwks_hash

    stub_request(:get, "#{domain}/.well-known/jwks.json")
      .to_return(
        status: 200,
        body: jwks.to_json,
        headers: { 'Content-Type' => 'application/json' }
      )
  end

  # Stubs a successful token refresh response
  #
  # @param domain [String] The Kinde domain
  # @param new_tokens [Hash] Token data to return
  def stub_token_refresh(domain: DEFAULT_DOMAIN, new_tokens: nil)
    new_tokens ||= {
      access_token: JwtHelpers.generate_access_token,
      refresh_token: JwtHelpers.generate_refresh_token,
      expires_in: 3600,
      token_type: 'bearer'
    }

    stub_request(:post, "#{domain}/oauth2/token")
      .with(body: /grant_type=refresh_token/)
      .to_return(
        status: 200,
        body: new_tokens.to_json,
        headers: { 'Content-Type' => 'application/json' }
      )
  end

  # Stubs a failed token refresh response
  #
  # @param domain [String] The Kinde domain
  # @param error [String] Error code
  # @param description [String] Error description
  def stub_token_refresh_failure(domain: DEFAULT_DOMAIN, error: 'invalid_grant', description: 'Token expired')
    stub_request(:post, "#{domain}/oauth2/token")
      .with(body: /grant_type=refresh_token/)
      .to_return(
        status: 400,
        body: { error: error, error_description: description }.to_json,
        headers: { 'Content-Type' => 'application/json' }
      )
  end

  # Stubs the account API for frontend client requests
  # Uses regex to match regardless of query parameters
  #
  # @param endpoint [String] API endpoint path (e.g., '/permissions')
  # @param response [Hash] Response body
  # @param status [Integer] HTTP status code
  # @param domain [String] The Kinde domain
  def stub_account_api(endpoint:, response:, status: 200, domain: DEFAULT_DOMAIN)
    stub_request(:get, /#{Regexp.escape(domain)}\/account_api\/v1#{Regexp.escape(endpoint)}/)
      .to_return(
        status: status,
        body: response.to_json,
        headers: { 'Content-Type' => 'application/json' }
      )
  end


  # Stubs an API error response
  # Uses regex to match regardless of query parameters
  #
  # @param endpoint [String] API endpoint path
  # @param status [Integer] HTTP status code
  # @param error [String] Error message
  # @param domain [String] The Kinde domain
  def stub_api_error(endpoint:, status:, error: 'Error occurred', domain: DEFAULT_DOMAIN)
    stub_request(:get, /#{Regexp.escape(domain)}\/account_api\/v1#{Regexp.escape(endpoint)}/)
      .to_return(
        status: status,
        body: { error: error }.to_json,
        headers: { 'Content-Type' => 'application/json' }
      )
  end

  # Stubs the user profile endpoint
  #
  # @param profile [Hash] User profile data
  # @param domain [String] The Kinde domain
  def stub_user_profile(profile:, domain: DEFAULT_DOMAIN)
    stub_request(:get, "#{domain}/oauth2/v2/user_profile")
      .to_return(
        status: 200,
        body: profile.to_json,
        headers: { 'Content-Type' => 'application/json' }
      )
  end

  # Stubs the portal link endpoint
  #
  # @param url [String] Portal URL to return
  # @param domain [String] The Kinde domain
  def stub_portal_link(url:, domain: DEFAULT_DOMAIN)
    stub_request(:get, /#{Regexp.escape(domain)}\/account_api\/v1\/portal_link/)
      .to_return(
        status: 200,
        body: { url: url }.to_json,
        headers: { 'Content-Type' => 'application/json' }
      )
  end

  # Stubs the authorization endpoint redirect
  #
  # @param domain [String] The Kinde domain
  def stub_authorization_endpoint(domain: DEFAULT_DOMAIN)
    stub_request(:get, /#{Regexp.escape(domain)}\/oauth2\/auth/)
      .to_return(status: 302, headers: { 'Location' => 'https://test.kinde.com/login' })
  end

  # Stubs the token exchange endpoint for authorization code flow
  #
  # @param tokens [Hash] Token response data
  # @param domain [String] The Kinde domain
  def stub_token_exchange(tokens:, domain: DEFAULT_DOMAIN)
    stub_request(:post, "#{domain}/oauth2/token")
      .with(body: /grant_type=authorization_code/)
      .to_return(
        status: 200,
        body: tokens.to_json,
        headers: { 'Content-Type' => 'application/json' }
      )
  end

  # Stubs client credentials token endpoint
  #
  # @param tokens [Hash] Token response data
  # @param domain [String] The Kinde domain
  def stub_client_credentials(tokens:, domain: DEFAULT_DOMAIN)
    stub_request(:post, "#{domain}/oauth2/token")
      .with(body: /grant_type=client_credentials/)
      .to_return(
        status: 200,
        body: tokens.to_json,
        headers: { 'Content-Type' => 'application/json' }
      )
  end

end

RSpec.configure do |config|
  config.include ApiHelpers
end

