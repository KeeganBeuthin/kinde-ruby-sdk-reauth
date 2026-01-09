# frozen_string_literal: true

# Provides JWT token generation utilities for testing authentication flows.
# Generates cryptographically valid tokens that can be verified by the SDK.
module JwtHelpers
  extend self

  # RSA key pair for signing test tokens
  # Generated once and cached for performance
  def rsa_key
    @rsa_key ||= OpenSSL::PKey::RSA.new(2048)
  end

  # JWK representation of the signing key
  def jwk
    @jwk ||= JWT::JWK.new(rsa_key, {
      kid: 'test-key-id',
      use: 'sig',
      alg: 'RS256'
    })
  end

  # JWKS hash for stubbing the well-known endpoint
  def jwks_hash
    @jwks_hash ||= JWT::JWK::Set.new(jwk).export
  end

  # Generates a valid access token with customizable claims
  #
  # @param claims [Hash] Custom claims to merge into the token
  # @return [String] Encoded JWT access token
  def generate_access_token(claims = {})
    default_claims = {
      'aud' => [],
      'azp' => 'test_client_id',
      'iat' => Time.now.to_i,
      'exp' => Time.now.to_i + 3600,
      'iss' => 'https://test.kinde.com',
      'jti' => SecureRandom.uuid,
      'sub' => "kp:#{SecureRandom.hex(16)}",
      'org_code' => 'org_test123',
      'permissions' => [],
      'roles' => [],
      'feature_flags' => {},
      'scp' => %w[openid offline email profile]
    }

    encode_token(default_claims.merge(claims))
  end

  # Generates a valid ID token with customizable claims
  #
  # @param claims [Hash] Custom claims to merge into the token
  # @return [String] Encoded JWT ID token
  def generate_id_token(claims = {})
    default_claims = {
      'aud' => ['test_client_id'],
      'iat' => Time.now.to_i,
      'exp' => Time.now.to_i + 3600,
      'iss' => 'https://test.kinde.com',
      'sub' => "kp:#{SecureRandom.hex(16)}",
      'nonce' => SecureRandom.hex(16),
      'email' => 'test@example.com',
      'email_verified' => true,
      'given_name' => 'Test',
      'family_name' => 'User',
      'picture' => 'https://example.com/avatar.jpg'
    }

    encode_token(default_claims.merge(claims))
  end

  # Generates a refresh token (opaque token for testing)
  #
  # @return [String] Opaque refresh token
  def generate_refresh_token
    SecureRandom.urlsafe_base64(32)
  end

  # Generates a complete token set for client initialization
  #
  # @param access_claims [Hash] Claims for the access token
  # @param id_claims [Hash] Claims for the ID token
  # @return [Hash] Complete token hash with all required fields
  def generate_token_set(access_claims: {}, id_claims: {})
    {
      access_token: generate_access_token(access_claims),
      id_token: generate_id_token(id_claims),
      refresh_token: generate_refresh_token,
      expires_at: Time.now.to_i + 3600,
      token_type: 'bearer',
      scope: 'openid offline email profile'
    }
  end

  # Generates an expired access token for testing token refresh flows
  #
  # @param claims [Hash] Additional claims
  # @return [String] Expired JWT token
  def generate_expired_token(claims = {})
    expired_claims = {
      'iat' => Time.now.to_i - 7200,
      'exp' => Time.now.to_i - 3600
    }

    generate_access_token(expired_claims.merge(claims))
  end

  # Generates a token expiring within specified seconds
  #
  # @param seconds [Integer] Seconds until expiration
  # @param claims [Hash] Additional claims
  # @return [String] JWT token expiring soon
  def generate_expiring_token(seconds:, claims: {})
    generate_access_token(claims.merge('exp' => Time.now.to_i + seconds))
  end

  # Decodes a token without verification (for test assertions)
  #
  # @param token [String] JWT token to decode
  # @return [Hash] Decoded payload
  def decode_token_payload(token)
    JWT.decode(token, nil, false).first
  end

  private

  def encode_token(claims)
    JWT.encode(claims, jwk.signing_key, 'RS256', kid: jwk[:kid])
  end
end

RSpec.configure do |config|
  config.include JwtHelpers
end



