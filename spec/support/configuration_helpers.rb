# frozen_string_literal: true

# Provides configuration utilities for testing.
# Helps manage SDK configuration state between tests.
module ConfigurationHelpers
  extend self

  # Resets the SDK configuration to a clean state
  def reset_configuration!
    KindeSdk.instance_variable_set(:@config, nil)
    
    if KindeSdk::Configuration.class_variable_defined?(:@@default)
      KindeSdk::Configuration.remove_class_variable(:@@default)
    end
  end

  # Configures the SDK with minimal valid settings
  #
  # @param overrides [Hash] Configuration overrides
  def configure_sdk(overrides = {})
    defaults = {
      domain: 'https://test.kinde.com',
      client_id: 'test_client_id',
      client_secret: 'test_client_secret',
      callback_url: 'http://localhost:3000/kinde/callback',
      logout_url: 'http://localhost:3000/kinde/logout_callback',
      pkce_enabled: true,
      auto_refresh_tokens: true,
      debugging: false
    }

    settings = defaults.merge(overrides)

    KindeSdk.configure do |config|
      settings.each do |key, value|
        config.public_send("#{key}=", value) if config.respond_to?("#{key}=")
      end
    end
  end

  # Creates a mock session hash for testing
  #
  # @param tokens [Hash] Token data to include in session
  # @return [Hash] Session-like hash with token data
  def build_mock_session(tokens = nil)
    session = {}
    if tokens
      session[:kinde_token_store] = {
        access_token: tokens[:access_token],
        refresh_token: tokens[:refresh_token],
        expires_at: tokens[:expires_at]
      }
    end
    session
  end

  # Creates a mock request environment for middleware testing
  #
  # @param session [Hash] Session data
  # @return [Hash] Rack environment hash
  def build_mock_env(session: {})
    {
      'rack.session' => session,
      'REQUEST_METHOD' => 'GET',
      'PATH_INFO' => '/',
      'HTTP_HOST' => 'localhost:3000'
    }
  end
end

RSpec.configure do |config|
  config.include ConfigurationHelpers

  # Automatically reset configuration after each test
  config.after(:each) do
    reset_configuration!
  end
end

