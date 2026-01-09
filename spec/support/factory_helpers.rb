# frozen_string_literal: true

# Provides factory methods for creating test data objects.
# Follows the factory pattern for consistent, customizable test fixtures.
module FactoryHelpers
  extend self

  # Creates a token hash suitable for SDK client initialization
  #
  # @param overrides [Hash] Values to override in the token set
  # @return [Hash] Token hash with symbolized keys
  def build_tokens(overrides = {})
    defaults = {
      access_token: generate_access_token,
      id_token: generate_id_token,
      refresh_token: generate_refresh_token,
      expires_at: Time.now.to_i + 3600
    }

    defaults.merge(overrides)
  end

  # Creates a token hash with specific feature flags embedded
  #
  # @param flags [Hash] Feature flags in token format (name => { t: type, v: value })
  # @return [Hash] Token hash with flags embedded
  def build_tokens_with_flags(flags)
    build_tokens(access_token: generate_access_token('feature_flags' => flags))
  end

  # Creates a token hash with specific permissions embedded
  #
  # @param permissions [Array<String>] Permission keys
  # @param org_code [String] Organization code
  # @return [Hash] Token hash with permissions embedded
  def build_tokens_with_permissions(permissions, org_code: 'org_test123')
    build_tokens(
      access_token: generate_access_token(
        'permissions' => permissions,
        'org_code' => org_code
      )
    )
  end

  # Creates a token hash with specific roles embedded
  #
  # @param roles [Array<Hash>] Role objects with id, key, name
  # @return [Hash] Token hash with roles embedded
  def build_tokens_with_roles(roles)
    build_tokens(access_token: generate_access_token('roles' => roles))
  end

  # Creates an expired token set for testing refresh flows
  #
  # @return [Hash] Token hash with expired access token
  def build_expired_tokens
    build_tokens(
      access_token: generate_expired_token,
      expires_at: Time.now.to_i - 3600
    )
  end

  # Creates a mock user profile response
  #
  # @param overrides [Hash] Values to override
  # @return [Hash] User profile data
  def build_user_profile(overrides = {})
    {
      id: "kp:#{SecureRandom.hex(16)}",
      sub: "kp:#{SecureRandom.hex(16)}",
      email: 'test@example.com',
      email_verified: true,
      given_name: 'Test',
      family_name: 'User',
      picture: 'https://example.com/avatar.jpg',
      provided_id: nil
    }.merge(overrides)
  end

  # Creates a mock role object
  #
  # @param key [String] Role key
  # @param name [String] Role display name (defaults to titleized key)
  # @return [Hash] Role object
  def build_role(key:, name: nil, id: nil)
    {
      id: id || SecureRandom.uuid,
      key: key,
      name: name || key.to_s.titleize
    }
  end

  # Creates a mock permission object
  #
  # @param key [String] Permission key
  # @param name [String] Permission display name
  # @return [Hash] Permission object
  def build_permission(key:, name: nil, id: nil)
    {
      id: id || SecureRandom.uuid,
      key: key,
      name: name || key.to_s.titleize
    }
  end

  # Creates a mock feature flag for token claims
  #
  # @param type [Symbol] Flag type (:boolean, :string, :integer)
  # @param value [Object] Flag value
  # @return [Hash] Flag object in token format
  def build_flag(type:, value:)
    type_code = case type
                when :boolean then 'b'
                when :string then 's'
                when :integer then 'i'
                else 's'
                end

    { 't' => type_code, 'v' => value }
  end

  # Creates a mock entitlement object
  #
  # @param feature_key [String] Feature key
  # @param options [Hash] Additional entitlement attributes
  # @return [Hash] Entitlement object
  def build_entitlement(feature_key:, **options)
    {
      id: options[:id] || SecureRandom.uuid,
      feature_key: feature_key,
      feature_name: options[:feature_name] || feature_key.titleize,
      price_name: options[:price_name] || 'Standard',
      fixed_charge: options[:fixed_charge] || 0,
      unit_amount: options[:unit_amount] || 1,
      entitlement_limit_max: options[:limit_max] || 100,
      entitlement_limit_min: options[:limit_min] || 1
    }
  end

  # Creates a paginated API response structure
  #
  # @param data_key [String] Key for the data array
  # @param items [Array] Items to include
  # @param has_more [Boolean] Whether more pages exist
  # @param next_page [String, nil] Token for next page
  # @return [Hash] Paginated response structure
  def build_paginated_response(data_key:, items:, has_more: false, next_page: nil)
    {
      'data' => {
        data_key => items
      },
      'metadata' => {
        'has_more' => has_more,
        'next_page_starting_after' => next_page
      }
    }
  end
end

RSpec.configure do |config|
  config.include FactoryHelpers
end



