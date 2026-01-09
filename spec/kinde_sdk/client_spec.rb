# frozen_string_literal: true

require 'spec_helper'

RSpec.describe KindeSdk::Client do
  include_context 'configured SDK'

  let(:tokens) { build_tokens }
  let(:auto_refresh_tokens) { true }
  let(:force_api) { false }

  subject(:client) { KindeSdk.client(tokens, auto_refresh_tokens, force_api) }

  describe '#initialize' do
    it 'stores the API client' do
      expect(client.kinde_api_client).to be_a(KindeApi::ApiClient)
    end

    it 'stores auto_refresh_tokens setting' do
      expect(client.auto_refresh_tokens).to eq(auto_refresh_tokens)
    end

    it 'creates a token store' do
      expect(client.token_store).to be_a(KindeSdk::TokenStore)
    end

    it 'stores force_api setting' do
      expect(client.force_api).to eq(force_api)
    end

    context 'with expired token and auto_refresh enabled' do
      let(:tokens) { build_expired_tokens }

      before do
        stub_token_refresh(domain: test_domain)
      end

      it 'attempts to refresh the token' do
        expect_any_instance_of(described_class).to receive(:refresh_token)
        client
      end
    end

    context 'with expired token and auto_refresh disabled' do
      let(:auto_refresh_tokens) { false }
      let(:tokens) { build_expired_tokens }

      it 'does not attempt to refresh' do
        expect_any_instance_of(described_class).not_to receive(:refresh_token)
        client
      end
    end
  end

  describe '#bearer_token' do
    it 'returns the access token' do
      expect(client.bearer_token).to eq(tokens[:access_token])
    end
  end

  describe '#tokens_hash' do
    it 'returns the tokens hash' do
      expect(client.tokens_hash).to include(:access_token)
    end
  end

  describe '#expires_at' do
    it 'returns the expiration time' do
      expect(client.expires_at).to eq(tokens[:expires_at])
    end
  end

  describe '#token_expired?' do
    it 'delegates to TokenManager' do
      allow(KindeSdk::TokenManager).to receive(:token_expired?).and_return(true)
      expect(client.token_expired?).to be true
    end
  end

  describe '#refresh_token' do
    let(:new_tokens) do
      {
        access_token: 'new_access_token',
        refresh_token: 'new_refresh_token',
        expires_at: Time.now.to_i + 3600
      }
    end

    context 'when refresh succeeds' do
      before do
        allow(KindeSdk::TokenManager).to receive(:refresh_tokens).and_return(new_tokens)
      end

      it 'returns the new tokens hash' do
        result = client.refresh_token
        expect(result).to be_a(Hash)
      end

      it 'updates the token store' do
        client.refresh_token
        expect(client.bearer_token).to eq('new_access_token')
      end
    end

    context 'when refresh fails' do
      before do
        allow(KindeSdk::TokenManager).to receive(:refresh_tokens).and_return(nil)
      end

      it 'returns nil' do
        expect(client.refresh_token).to be_nil
      end
    end
  end

  describe '#get_claim' do
    let(:sub) { "kp:#{SecureRandom.hex(16)}" }
    let(:org_code) { 'org_test123' }
    let(:tokens) do
      build_tokens(
        access_token: generate_access_token(
          'sub' => sub,
          'org_code' => org_code,
          'custom_claim' => 'custom_value'
        )
      )
    end

    it 'extracts claim from access token' do
      result = client.get_claim('sub')
      expect(result[:value]).to eq(sub)
    end

    it 'returns claim name and value' do
      result = client.get_claim('org_code')
      expect(result).to eq({ name: 'org_code', value: org_code })
    end

    it 'extracts custom claims' do
      result = client.get_claim('custom_claim')
      expect(result[:value]).to eq('custom_value')
    end

    it 'returns nil for non-existent claims' do
      result = client.get_claim('non_existent')
      expect(result).to be_nil
    end

    context 'with id_token' do
      let(:tokens) do
        build_tokens(
          id_token: generate_id_token('email' => 'test@example.com')
        )
      end

      it 'extracts claim from id token when specified' do
        result = client.get_claim('email', :id_token)
        expect(result[:value]).to eq('test@example.com')
      end
    end

    context 'with auto_refresh and expired token' do
      before do
        allow(client).to receive(:token_expired?).and_return(true)
        stub_token_refresh(domain: test_domain)
      end

      it 'refreshes token before reading claim' do
        expect(client).to receive(:refresh_token)
        client.get_claim('sub')
      end
    end
  end

  describe '#generate_portal_url' do
    it 'raises error for relative return_url' do
      expect {
        client.generate_portal_url(domain: test_domain, return_url: '/home')
      }.to raise_error(StandardError, /absolute URL/)
    end
  end

  describe '#generatePortalUrl (alias)' do
    it 'is callable' do
      expect(client).to respond_to(:generatePortalUrl)
    end

    it 'raises error without bearer token' do
      allow(client.token_store).to receive(:bearer_token).and_return(nil)
      expect {
        client.generatePortalUrl('https://app.example.com')
      }.to raise_error(KindeSdk::APIError, /Access Token not found/)
    end

    it 'raises error for relative URL' do
      expect {
        client.generatePortalUrl('/relative')
      }.to raise_error(KindeSdk::APIError, /absolute URL/)
    end
  end

  describe '#oauth' do
    it 'returns an OAuth API instance' do
      expect(client.oauth).to be_a(KindeApi::OAuthApi)
    end

    it 'adds get_user backward compatibility method' do
      expect(client.oauth).to respond_to(:get_user)
    end

    it 'preserves get_user_profile_v2 method' do
      expect(client.oauth).to respond_to(:get_user_profile_v2)
    end
  end

  describe '#frontend' do
    it 'returns a FrontendClient instance' do
      expect(client.frontend).to be_a(KindeSdk::Internal::FrontendClient)
    end

    it 'returns the same instance on subsequent calls' do
      first_call = client.frontend
      second_call = client.frontend
      expect(first_call).to be(second_call)
    end
  end

  describe 'API wrappers' do
    before do
      stub_account_api(
        endpoint: '/entitlements',
        response: build_paginated_response(
          data_key: 'entitlements',
          items: [],
          has_more: false
        )
      )
    end

    describe '#entitlements' do
      it 'returns entitlements from frontend API' do
        result = client.entitlements
        expect(result).not_to be_nil
      end
    end

    describe '#user_feature_flags' do
      before do
        stub_account_api(
          endpoint: '/feature_flags',
          response: build_paginated_response(
            data_key: 'feature_flags',
            items: [],
            has_more: false
          )
        )
      end

      it 'returns feature flags from frontend API' do
        result = client.user_feature_flags
        expect(result).not_to be_nil
      end
    end

    describe '#user_permissions' do
      before do
        stub_account_api(
          endpoint: '/permissions',
          response: {
            'data' => { 'permissions' => [] },
            'metadata' => { 'has_more' => false }
          }
        )
      end

      it 'returns permissions from frontend API' do
        result = client.user_permissions
        expect(result).not_to be_nil
      end
    end

    describe '#user_properties' do
      before do
        stub_account_api(
          endpoint: '/properties',
          response: {
            'data' => { 'properties' => [] },
            'metadata' => { 'has_more' => false }
          }
        )
      end

      it 'returns properties from frontend API' do
        result = client.user_properties
        expect(result).not_to be_nil
      end
    end

    describe '#user_roles' do
      before do
        stub_account_api(
          endpoint: '/roles',
          response: {
            'data' => { 'roles' => [] },
            'metadata' => { 'has_more' => false }
          }
        )
      end

      it 'returns roles from frontend API' do
        result = client.user_roles
        expect(result).not_to be_nil
      end
    end
  end

  describe 'dynamic API method generation' do
    it 'generates methods for all KindeApi API classes' do
      # Test a sampling of generated methods
      expect(client).to respond_to(:users)
      expect(client).to respond_to(:organizations)
      expect(client).to respond_to(:roles)
    end

    it 'returns API instances with token refresh wrapper' do
      users_api = client.users
      expect(users_api).to be_a(KindeApi::UsersApi)
    end
  end

  describe 'PortalPage constants' do
    it 'defines ORGANIZATION_DETAILS' do
      expect(KindeSdk::PortalPage::ORGANIZATION_DETAILS).to eq('organization_details')
    end

    it 'defines ORGANIZATION_MEMBERS' do
      expect(KindeSdk::PortalPage::ORGANIZATION_MEMBERS).to eq('organization_members')
    end

    it 'defines PROFILE' do
      expect(KindeSdk::PortalPage::PROFILE).to eq('profile')
    end
  end
end

