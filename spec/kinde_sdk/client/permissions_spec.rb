# frozen_string_literal: true

require 'spec_helper'

RSpec.describe KindeSdk::Client::Permissions do
  include_context 'authenticated client'

  let(:org_code) { 'org_test123' }
  let(:permissions) { %w[read:users write:users delete:users read:reports] }
  let(:token_claims) { { 'permissions' => permissions, 'org_code' => org_code } }

  describe '#get_permissions' do
    context 'soft check (token-based)' do
      it 'extracts permissions from token claims' do
        result = client.get_permissions
        expect(result[:permissions]).to eq(permissions)
      end

      it 'includes organization code' do
        result = client.get_permissions
        expect(result[:org_code]).to eq(org_code)
      end

      it 'returns correct structure' do
        result = client.get_permissions
        expect(result).to have_key(:org_code)
        expect(result).to have_key(:permissions)
      end

      it 'does not make API calls' do
        client.get_permissions
        expect(WebMock).not_to have_requested(:get, /account_api/)
      end
    end

    context 'with empty permissions' do
      let(:token_claims) { { 'permissions' => [], 'org_code' => org_code } }

      it 'returns empty permissions array' do
        result = client.get_permissions
        expect(result[:permissions]).to eq([])
      end

      it 'still includes org_code' do
        result = client.get_permissions
        expect(result[:org_code]).to eq(org_code)
      end
    end

    context 'with nil permissions' do
      let(:token_claims) { { 'permissions' => nil, 'org_code' => org_code } }

      it 'returns empty permissions array' do
        result = client.get_permissions
        expect(result[:permissions]).to eq([])
      end
    end

    context 'with missing permissions claim' do
      let(:token_claims) { { 'org_code' => org_code } }

      it 'returns empty permissions array' do
        result = client.get_permissions
        expect(result[:permissions]).to eq([])
      end
    end

    context 'hard check (API-based)' do
      let(:api_permissions) do
        [
          { 'id' => 'perm_1', 'key' => 'admin:all', 'name' => 'Admin Access' },
          { 'id' => 'perm_2', 'key' => 'manage:billing', 'name' => 'Billing Management' }
        ]
      end

      before do
        stub_account_api(
          endpoint: '/permissions',
          response: {
            'data' => {
              'org_code' => 'org_from_api',
              'permissions' => api_permissions
            },
            'metadata' => { 'has_more' => false }
          }
        )
      end

      it 'fetches permissions from API when force_api is true' do
        client.get_permissions(force_api: true)
        expect(WebMock).to have_requested(:get, /permissions/)
      end

      it 'returns API permissions instead of token permissions' do
        result = client.get_permissions(force_api: true)
        expect(result[:permissions]).to include('admin:all', 'manage:billing')
        expect(result[:permissions]).not_to include('read:users')
      end

      it 'includes org_code in response' do
        result = client.get_permissions(force_api: true)
        expect(result).to have_key(:org_code)
      end
    end

    context 'with legacy positional argument' do
      it 'accepts token_type as symbol' do
        result = client.get_permissions(:access_token)
        expect(result[:permissions]).to eq(permissions)
      end
    end
  end

  describe '#get_permission' do
    context 'when permission is granted' do
      it 'returns is_granted as true' do
        result = client.get_permission('read:users')
        expect(result[:is_granted]).to be true
      end

      it 'includes org_code' do
        result = client.get_permission('read:users')
        expect(result[:org_code]).to eq(org_code)
      end
    end

    context 'when permission is not granted' do
      it 'returns is_granted as false' do
        result = client.get_permission('admin:all')
        expect(result[:is_granted]).to be false
      end
    end

    context 'with API-based check' do
      let(:api_permissions) do
        [{ 'id' => 'perm_1', 'key' => 'api:permission', 'name' => 'API Permission' }]
      end

      before do
        stub_account_api(
          endpoint: '/permissions',
          response: {
            'data' => {
              'org_code' => org_code,
              'permissions' => api_permissions
            },
            'metadata' => { 'has_more' => false }
          }
        )
      end

      it 'checks against API permissions' do
        result = client.get_permission('api:permission', force_api: true)
        expect(result[:is_granted]).to be true
      end
    end
  end

  describe '#permission_granted?' do
    it 'returns true for granted permission' do
      expect(client.permission_granted?('read:users')).to be true
    end

    it 'returns false for non-granted permission' do
      expect(client.permission_granted?('admin:all')).to be false
    end

    it 'accepts options hash' do
      expect(client.permission_granted?('read:users', force_api: false)).to be true
    end
  end

  describe '#getPermissions (alias)' do
    it 'is callable as an alias method' do
      expect(client).to respond_to(:getPermissions)
    end
  end

  describe '#getAllPermissions (PHP SDK compatible alias)' do
    let(:api_permissions) do
      [
        { 'id' => 'perm_1', 'key' => 'perm_one', 'name' => 'Permission One' },
        { 'id' => 'perm_2', 'key' => 'perm_two', 'name' => 'Permission Two' }
      ]
    end

    before do
      stub_account_api(
        endpoint: '/permissions',
        response: {
          'data' => {
            'org_code' => org_code,
            'permissions' => api_permissions
          },
          'metadata' => { 'has_more' => false }
        }
      )
    end

    it 'returns array of permission keys' do
      result = client.getAllPermissions
      expect(result).to be_an(Array)
    end
  end

  describe '#all_permissions (Ruby alias)' do
    it 'is an alias for getAllPermissions' do
      expect(client.method(:all_permissions)).to eq(client.method(:getAllPermissions))
    end
  end

  describe 'Hasura claim fallback' do
    let(:token_claims) do
      {
        'permissions' => nil,
        'x-hasura-permissions' => %w[hasura:read hasura:write],
        'org_code' => nil,
        'x-hasura-org-code' => 'hasura_org'
      }
    end

    it 'falls back to x-hasura-permissions claim' do
      result = client.get_permissions
      expect(result[:permissions]).to eq(%w[hasura:read hasura:write])
    end

    it 'falls back to x-hasura-org-code claim' do
      result = client.get_permissions
      expect(result[:org_code]).to eq('hasura_org')
    end
  end

  describe 'API error handling' do
    let(:token_claims) { { 'permissions' => %w[fallback:permission] } }

    context 'when API returns 401 Unauthorized' do
      before do
        stub_api_error(endpoint: '/permissions', status: 401, error: 'Unauthorized')
      end

      it 'falls back to token claims' do
        result = client.get_permissions(force_api: true)
        expect(result[:permissions]).to include('fallback:permission')
      end
    end

    context 'when API returns 500 Server Error' do
      before do
        stub_api_error(endpoint: '/permissions', status: 500, error: 'Server Error')
      end

      it 'falls back to token claims' do
        result = client.get_permissions(force_api: true)
        expect(result[:permissions]).to include('fallback:permission')
      end
    end
  end


  describe 'typed permissions' do
    it 'preserves permission key strings' do
      result = client.get_permissions
      expect(result[:permissions]).to all(be_a(String))
    end

    it 'maintains permission ordering' do
      result = client.get_permissions
      expect(result[:permissions].first).to eq('read:users')
    end
  end
end

