# frozen_string_literal: true

require 'spec_helper'

RSpec.describe KindeSdk::Configuration do
  after(:each) do
    reset_configuration!
  end

  describe '#initialize' do
    subject(:config) { described_class.new }

    it 'sets default authorize_url' do
      expect(config.authorize_url).to eq('/oauth2/auth')
    end

    it 'sets default token_url' do
      expect(config.token_url).to eq('/oauth2/token')
    end

    it 'sets default jwks_url' do
      expect(config.jwks_url).to eq('/.well-known/jwks.json')
    end

    it 'enables PKCE by default' do
      expect(config.pkce_enabled).to be true
    end

    it 'enables auto_refresh_tokens by default' do
      expect(config.auto_refresh_tokens).to be true
    end

    it 'disables debugging by default' do
      expect(config.debugging).to be false
    end

    it 'disables force_api by default' do
      expect(config.force_api).to be false
    end

    it 'sets default scope' do
      expect(config.scope).to eq('openid offline email profile')
    end

    it 'initializes with a logger or Rails.logger' do
      # Logger is set from Rails.logger if Rails is defined, otherwise STDOUT
      # In test environment, Rails is defined so this depends on Rails.logger
      expect(config).to respond_to(:logger)
    end
  end

  describe '#initialize with block' do
    subject(:config) do
      described_class.new do |c|
        c.domain = 'https://custom.kinde.com'
        c.client_id = 'custom_client_id'
      end
    end

    it 'yields the configuration for customization' do
      expect(config.domain).to eq('https://custom.kinde.com')
      expect(config.client_id).to eq('custom_client_id')
    end
  end

  describe '.default' do
    it 'returns a shared configuration instance' do
      config1 = described_class.default
      config2 = described_class.default
      expect(config1).to be(config2)
    end

    it 'creates a new instance if none exists' do
      expect(described_class.default).to be_a(described_class)
    end
  end

  describe '#configure' do
    subject(:config) { described_class.new }

    it 'yields self for configuration' do
      config.configure do |c|
        c.domain = 'https://configured.kinde.com'
      end

      expect(config.domain).to eq('https://configured.kinde.com')
    end

    it 'does nothing without a block' do
      expect { config.configure }.not_to raise_error
    end
  end

  describe '#oauth_client' do
    subject(:config) do
      described_class.new do |c|
        c.domain = 'https://test.kinde.com'
        c.client_id = 'test_client'
        c.client_secret = 'test_secret'
      end
    end

    it 'returns an OAuth2::Client instance' do
      expect(config.oauth_client).to be_a(OAuth2::Client)
    end

    it 'configures the client with the correct site' do
      client = config.oauth_client
      expect(client.site).to eq('https://test.kinde.com')
    end

    it 'allows parameter overrides' do
      client = config.oauth_client(
        client_id: 'override_client',
        domain: 'https://override.kinde.com'
      )

      expect(client.id).to eq('override_client')
      expect(client.site).to eq('https://override.kinde.com')
    end

    it 'uses custom authorize_url' do
      client = config.oauth_client(authorize_url: '/custom/auth')
      expect(client.options[:authorize_url]).to eq('/custom/auth')
    end

    it 'uses custom token_url' do
      client = config.oauth_client(token_url: '/custom/token')
      expect(client.options[:token_url]).to eq('/custom/token')
    end
  end

  describe 'attribute accessors' do
    subject(:config) { described_class.new }

    describe '#domain' do
      it 'can be set and retrieved' do
        config.domain = 'https://example.kinde.com'
        expect(config.domain).to eq('https://example.kinde.com')
      end
    end

    describe '#client_id' do
      it 'can be set and retrieved' do
        config.client_id = 'my_client_id'
        expect(config.client_id).to eq('my_client_id')
      end
    end

    describe '#client_secret' do
      it 'can be set and retrieved' do
        config.client_secret = 'my_secret'
        expect(config.client_secret).to eq('my_secret')
      end
    end

    describe '#callback_url' do
      it 'can be set and retrieved' do
        config.callback_url = 'http://localhost:3000/callback'
        expect(config.callback_url).to eq('http://localhost:3000/callback')
      end
    end

    describe '#logout_url' do
      it 'can be set and retrieved' do
        config.logout_url = 'http://localhost:3000/logout'
        expect(config.logout_url).to eq('http://localhost:3000/logout')
      end
    end

    describe '#scope' do
      it 'can be customized' do
        config.scope = 'openid profile'
        expect(config.scope).to eq('openid profile')
      end
    end

    describe '#pkce_enabled' do
      it 'can be disabled' do
        config.pkce_enabled = false
        expect(config.pkce_enabled).to be false
      end
    end

    describe '#auto_refresh_tokens' do
      it 'can be disabled' do
        config.auto_refresh_tokens = false
        expect(config.auto_refresh_tokens).to be false
      end
    end

    describe '#force_api' do
      it 'can be enabled' do
        config.force_api = true
        expect(config.force_api).to be true
      end
    end

    describe '#debugging' do
      it 'can be enabled' do
        config.debugging = true
        expect(config.debugging).to be true
      end
    end

    describe '#expected_issuer' do
      it 'can be set for JWT validation' do
        config.expected_issuer = 'https://issuer.kinde.com'
        expect(config.expected_issuer).to eq('https://issuer.kinde.com')
      end
    end

    describe '#expected_audience' do
      it 'can be set for JWT validation' do
        config.expected_audience = 'my_api_audience'
        expect(config.expected_audience).to eq('my_api_audience')
      end
    end

    describe '#logger' do
      it 'can be customized' do
        custom_logger = Logger.new($stdout)
        config.logger = custom_logger
        expect(config.logger).to be(custom_logger)
      end
    end
  end

  describe 'integration with KindeSdk.configure' do
    it 'sets the global configuration' do
      KindeSdk.configure do |c|
        c.domain = 'https://global.kinde.com'
        c.client_id = 'global_client'
      end

      expect(KindeSdk.config.domain).to eq('https://global.kinde.com')
      expect(KindeSdk.config.client_id).to eq('global_client')
    end

    it 'returns the configuration without a block' do
      config = KindeSdk.configure
      expect(config).to be_a(described_class)
    end
  end
end

