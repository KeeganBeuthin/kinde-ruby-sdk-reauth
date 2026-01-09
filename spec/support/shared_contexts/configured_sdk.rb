# frozen_string_literal: true

# Provides a pre-configured SDK environment for testing.
# Use this context when tests require the SDK to be properly initialized.
RSpec.shared_context 'configured SDK' do
  let(:test_domain) { 'https://test.kinde.com' }
  let(:test_client_id) { 'test_client_id' }
  let(:test_client_secret) { 'test_client_secret' }
  let(:test_callback_url) { 'http://localhost:3000/kinde/callback' }
  let(:test_logout_url) { 'http://localhost:3000/kinde/logout_callback' }

  before do
    stub_jwks_endpoint(domain: test_domain)

    KindeSdk.configure do |config|
      config.domain = test_domain
      config.client_id = test_client_id
      config.client_secret = test_client_secret
      config.callback_url = test_callback_url
      config.logout_url = test_logout_url
      config.pkce_enabled = true
      config.auto_refresh_tokens = true
      config.debugging = false
    end
  end

  after do
    # Reset configuration to avoid test pollution
    KindeSdk.instance_variable_set(:@config, nil)
    KindeSdk::Configuration.class_variable_set(:@@default, nil) if KindeSdk::Configuration.class_variable_defined?(:@@default)
  end
end

RSpec.configure do |config|
  config.include_context 'configured SDK', :configured_sdk
end



