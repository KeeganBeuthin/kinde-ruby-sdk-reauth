# frozen_string_literal: true

# Provides an authenticated client instance for testing client functionality.
# Includes the configured SDK context and adds a ready-to-use client.
RSpec.shared_context 'authenticated client' do
  include_context 'configured SDK'

  let(:token_claims) { {} }
  let(:tokens) { build_tokens(access_token: generate_access_token(token_claims)) }
  let(:client) { KindeSdk.client(tokens) }

  # Common claim configurations for easy reuse
  let(:org_code) { 'org_test123' }
  let(:user_sub) { "kp:#{SecureRandom.hex(16)}" }

  before do
    # Ensure token refresh is stubbed for tests that trigger auto-refresh
    stub_token_refresh(domain: test_domain)
  end
end

# Context for testing with specific permissions
RSpec.shared_context 'client with permissions' do
  include_context 'authenticated client'

  let(:permissions) { %w[read:users write:users] }
  let(:token_claims) { { 'permissions' => permissions, 'org_code' => org_code } }
end

# Context for testing with specific roles
RSpec.shared_context 'client with roles' do
  include_context 'authenticated client'

  let(:roles) do
    [
      { 'id' => 'role_1', 'key' => 'admin', 'name' => 'Administrator' },
      { 'id' => 'role_2', 'key' => 'user', 'name' => 'User' }
    ]
  end
  let(:token_claims) { { 'roles' => roles } }
end

# Context for testing with feature flags
RSpec.shared_context 'client with feature flags' do
  include_context 'authenticated client'

  let(:feature_flags) do
    {
      'dark_mode' => { 't' => 'b', 'v' => true },
      'max_items' => { 't' => 'i', 'v' => 100 },
      'theme' => { 't' => 's', 'v' => 'modern' }
    }
  end
  let(:token_claims) { { 'feature_flags' => feature_flags } }
end

# Context for testing with an expired token
RSpec.shared_context 'client with expired token' do
  include_context 'authenticated client'

  let(:tokens) do
    {
      access_token: generate_expired_token,
      refresh_token: generate_refresh_token,
      expires_at: Time.now.to_i - 3600
    }
  end
end

RSpec.configure do |config|
  config.include_context 'authenticated client', :authenticated_client
  config.include_context 'client with permissions', :with_permissions
  config.include_context 'client with roles', :with_roles
  config.include_context 'client with feature flags', :with_feature_flags
  config.include_context 'client with expired token', :with_expired_token
end

