# frozen_string_literal: true

require 'spec_helper'

RSpec.describe KindeSdk::Internal::FrontendClient do
  include_context 'configured SDK'

  let(:tokens) { build_tokens }
  let(:token_store) { KindeSdk::TokenStore.new(tokens) }
  let(:domain) { test_domain }

  subject(:client) { described_class.new(token_store, domain) }

  describe '#initialize' do
    it 'stores the token store' do
      expect(client.instance_variable_get(:@token_store)).to eq(token_store)
    end

    it 'stores the domain' do
      expect(client.instance_variable_get(:@domain)).to eq(domain)
    end

    it 'constructs the base URI' do
      expect(client.instance_variable_get(:@base_uri)).to eq("#{domain}/account_api/v1")
    end
  end

  describe '#get_entitlements' do
    let(:response) do
      {
        'data' => {
          'entitlements' => [
            { 'id' => 'ent_1', 'feature_key' => 'feature_1' }
          ]
        },
        'metadata' => { 'has_more' => false }
      }
    end

    before do
      stub_account_api(endpoint: '/entitlements', response: response)
    end

    it 'makes a GET request to the entitlements endpoint' do
      client.get_entitlements
      expect(WebMock).to have_requested(:get, /entitlements/)
    end

    it 'includes authorization header' do
      client.get_entitlements
      expect(WebMock).to have_requested(:get, /entitlements/)
        .with(headers: { 'Authorization' => "Bearer #{tokens[:access_token]}" })
    end

    it 'returns parsed response as OpenStruct' do
      result = client.get_entitlements
      expect(result.data.entitlements).to be_an(Array)
    end

    context 'with pagination parameters' do
      it 'passes page_size parameter' do
        client.get_entitlements(page_size: 50)
        expect(WebMock).to have_requested(:get, /entitlements/)
          .with(query: hash_including('page_size' => '50'))
      end

      it 'passes starting_after parameter' do
        client.get_entitlements(starting_after: 'cursor_123')
        expect(WebMock).to have_requested(:get, /entitlements/)
          .with(query: hash_including('starting_after' => 'cursor_123'))
      end
    end
  end

  describe '#get_entitlement' do
    let(:response) do
      {
        'data' => {
          'entitlement' => { 'id' => 'ent_1', 'feature_key' => 'test_key' }
        }
      }
    end

    before do
      stub_request(:get, /#{Regexp.escape(domain)}\/account_api\/v1\/entitlement/)
        .to_return(
          status: 200,
          body: response.to_json,
          headers: { 'Content-Type' => 'application/json' }
        )
    end

    it 'passes the key parameter' do
      client.get_entitlement('test_key')
      expect(WebMock).to have_requested(:get, /entitlement/)
    end

    context 'when entitlement not found' do
      before do
        stub_request(:get, /#{Regexp.escape(domain)}\/account_api\/v1\/entitlement/)
          .to_return(status: 404, body: '{}', headers: { 'Content-Type' => 'application/json' })
      end

      it 'returns nil' do
        expect(client.get_entitlement('missing')).to be_nil
      end
    end
  end

  describe '#get_user_permissions' do
    let(:response) do
      {
        'data' => {
          'permissions' => [{ 'id' => 'perm_1', 'key' => 'read:users' }]
        },
        'metadata' => { 'has_more' => false }
      }
    end

    before do
      stub_account_api(endpoint: '/permissions', response: response)
    end

    it 'makes a GET request to the permissions endpoint' do
      client.get_user_permissions
      expect(WebMock).to have_requested(:get, /permissions/)
    end

    it 'returns parsed response' do
      result = client.get_user_permissions
      expect(result.data.permissions).to be_an(Array)
    end
  end

  describe '#get_user_properties' do
    let(:response) do
      {
        'data' => {
          'properties' => [{ 'key' => 'custom_field', 'value' => 'custom_value' }]
        },
        'metadata' => { 'has_more' => false }
      }
    end

    before do
      stub_account_api(endpoint: '/properties', response: response)
    end

    it 'makes a GET request to the properties endpoint' do
      client.get_user_properties
      expect(WebMock).to have_requested(:get, /properties/)
    end
  end

  describe '#get_user_roles' do
    let(:response) do
      {
        'data' => {
          'roles' => [{ 'id' => 'role_1', 'key' => 'admin', 'name' => 'Admin' }]
        },
        'metadata' => { 'has_more' => false }
      }
    end

    before do
      stub_account_api(endpoint: '/roles', response: response)
    end

    it 'makes a GET request to the roles endpoint' do
      client.get_user_roles
      expect(WebMock).to have_requested(:get, /roles/)
    end
  end

  describe '#get_feature_flags' do
    let(:response) do
      {
        'data' => {
          'feature_flags' => [{ 'key' => 'dark_mode', 'value' => true, 'type' => 'boolean' }]
        },
        'metadata' => { 'has_more' => false }
      }
    end

    before do
      stub_account_api(endpoint: '/feature_flags', response: response)
    end

    it 'makes a GET request to the feature_flags endpoint' do
      client.get_feature_flags
      expect(WebMock).to have_requested(:get, /feature_flags/)
    end
  end

  describe '#get_portal_link' do
    let(:response) do
      { 'url' => 'https://portal.kinde.com/user/profile?token=abc123' }
    end

    before do
      stub_portal_link(url: response['url'], domain: domain)
    end

    it 'makes a GET request to the portal_link endpoint' do
      client.get_portal_link
      expect(WebMock).to have_requested(:get, /portal_link/)
    end

    it 'passes subnav parameter' do
      client.get_portal_link(subnav: 'profile')
      expect(WebMock).to have_requested(:get, /portal_link/)
        .with(query: hash_including('subnav' => 'profile'))
    end

    it 'passes return_url parameter' do
      client.get_portal_link(return_url: 'https://app.example.com')
      expect(WebMock).to have_requested(:get, /portal_link/)
        .with(query: hash_including('return_url' => 'https://app.example.com'))
    end
  end

  describe '#get_user_profile_v2' do
    let(:profile) do
      {
        'id' => 'user_123',
        'email' => 'test@example.com',
        'given_name' => 'Test',
        'family_name' => 'User'
      }
    end

    before do
      stub_user_profile(profile: profile, domain: domain)
    end

    it 'makes a GET request to the user profile endpoint' do
      client.get_user_profile_v2
      expect(WebMock).to have_requested(:get, "#{domain}/oauth2/v2/user_profile")
    end

    it 'returns parsed profile as OpenStruct' do
      result = client.get_user_profile_v2
      expect(result.id).to eq('user_123')
      expect(result.email).to eq('test@example.com')
    end
  end

  describe 'error handling' do
    context 'when API returns 401 Unauthorized' do
      before do
        stub_api_error(endpoint: '/entitlements', status: 401, error: 'Invalid token')
      end

      it 'raises AuthenticationError' do
        expect { client.get_entitlements }
          .to raise_error(KindeSdk::AuthenticationError, /Invalid or expired token/)
      end
    end

    context 'when API returns 403 Forbidden' do
      before do
        stub_api_error(endpoint: '/entitlements', status: 403, error: 'Forbidden')
      end

      it 'raises AuthorizationError' do
        expect { client.get_entitlements }
          .to raise_error(KindeSdk::AuthorizationError, /Insufficient permissions/)
      end
    end

    context 'when API returns 404 Not Found' do
      before do
        stub_api_error(endpoint: '/entitlements', status: 404)
      end

      it 'returns nil' do
        expect(client.get_entitlements).to be_nil
      end
    end

    context 'when API returns 429 Rate Limited' do
      before do
        stub_api_error(endpoint: '/entitlements', status: 429, error: 'Too many requests')
      end

      it 'raises RateLimitError' do
        expect { client.get_entitlements }
          .to raise_error(KindeSdk::RateLimitError, /Too many requests/)
      end
    end

    context 'when API returns 500 Server Error' do
      before do
        stub_api_error(endpoint: '/entitlements', status: 500, error: 'Internal error')
      end

      it 'raises APIError' do
        expect { client.get_entitlements }
          .to raise_error(KindeSdk::APIError, /API request failed/)
      end
    end
  end

  describe 'authorization header' do
    before do
      stub_account_api(
        endpoint: '/entitlements',
        response: { 'data' => { 'entitlements' => [] }, 'metadata' => { 'has_more' => false } }
      )
    end

    it 'sends bearer token in authorization header' do
      client.get_entitlements
      expect(WebMock).to have_requested(:get, /entitlements/)
        .with(headers: { 'Authorization' => /^Bearer / })
    end

    it 'sends content-type header' do
      client.get_entitlements
      expect(WebMock).to have_requested(:get, /entitlements/)
        .with(headers: { 'Content-Type' => 'application/json' })
    end
  end

  describe 'compact query parameters' do
    before do
      stub_account_api(
        endpoint: '/entitlements',
        response: { 'data' => { 'entitlements' => [] }, 'metadata' => { 'has_more' => false } }
      )
    end

    it 'excludes nil parameters from query string' do
      client.get_entitlements(page_size: 10, starting_after: nil)

      # Verify starting_after is not in the request
      expect(WebMock).to have_requested(:get, /entitlements/)
        .with { |req| !req.uri.query&.include?('starting_after') }
    end
  end
end

