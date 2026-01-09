# frozen_string_literal: true

require 'spec_helper'

RSpec.describe KindeSdk::Client::Roles do
  include_context 'authenticated client'

  describe 'module inclusion' do
    it 'is included in the Client class' do
      expect(client).to respond_to(:get_roles)
      expect(client).to respond_to(:has_roles?)
      expect(client).to respond_to(:getRoles)
      expect(client).to respond_to(:hasRoles)
    end
  end

  describe '#get_roles' do
    context 'soft check (token-based)' do
      let(:roles) do
        [
          { 'id' => 'role_1', 'key' => 'admin', 'name' => 'Administrator' },
          { 'id' => 'role_2', 'key' => 'user', 'name' => 'Standard User' }
        ]
      end
      let(:token_claims) { { 'roles' => roles } }

      it 'extracts roles from token claims' do
        result = client.get_roles
        expect(result.length).to eq(2)
      end

      it 'returns roles with correct structure' do
        result = client.get_roles
        admin_role = result.find { |r| r[:key] == 'admin' }

        expect(admin_role).to include(
          id: 'role_1',
          key: 'admin',
          name: 'Administrator'
        )
      end

      it 'normalizes hash-based role data correctly' do
        # This tests the fix for extract_field - hashes should be handled before respond_to? check
        result = client.get_roles
        expect(result.first[:key]).to eq('admin')
        expect(result.first[:id]).to eq('role_1')
      end

      it 'does not make API calls when roles exist in token' do
        client.get_roles
        expect(WebMock).not_to have_requested(:get, /account_api/)
      end
    end

    context 'with empty roles in token' do
      let(:token_claims) { { 'roles' => [] } }

      before do
        stub_account_api(
          endpoint: '/roles',
          response: {
            'data' => { 'org_code' => 'org_test', 'roles' => [] },
            'metadata' => { 'has_more' => false }
          }
        )
      end

      it 'falls back to API automatically (smart fallback)' do
        client.get_roles
        expect(WebMock).to have_requested(:get, /roles/)
      end
    end

    context 'with nil roles in token' do
      let(:token_claims) { { 'roles' => nil } }

      before do
        stub_account_api(
          endpoint: '/roles',
          response: {
            'data' => { 'org_code' => 'org_test', 'roles' => [] },
            'metadata' => { 'has_more' => false }
          }
        )
      end

      it 'falls back to API automatically' do
        client.get_roles
        expect(WebMock).to have_requested(:get, /roles/)
      end
    end

    context 'hard check (API-based)' do
      let(:api_roles) do
        [
          { 'id' => 'role_api_1', 'key' => 'admin', 'name' => 'Administrator' },
          { 'id' => 'role_api_2', 'key' => 'manager', 'name' => 'Manager' }
        ]
      end

      before do
        stub_account_api(
          endpoint: '/roles',
          response: {
            'data' => { 'org_code' => 'org_test', 'roles' => api_roles },
            'metadata' => { 'has_more' => false }
          }
        )
      end

      it 'fetches roles from API when force_api is true' do
        client.get_roles(force_api: true)
        expect(WebMock).to have_requested(:get, /roles/)
      end

      it 'returns API roles instead of token roles' do
        # Token has different roles
        result = client.get_roles(force_api: true)
        role_keys = result.map { |r| r[:key] }
        expect(role_keys).to include('admin', 'manager')
      end

      it 'includes authorization header in API requests' do
        client.get_roles(force_api: true)
        expect(WebMock).to have_requested(:get, /roles/)
          .with(headers: { 'Authorization' => /^Bearer / })
      end
    end

    context 'with legacy positional argument' do
      let(:roles) { [{ 'id' => 'role_1', 'key' => 'admin', 'name' => 'Admin' }] }
      let(:token_claims) { { 'roles' => roles } }

      it 'accepts token_type as positional argument' do
        result = client.get_roles(:access_token)
        expect(result.length).to eq(1)
      end
    end
  end

  describe '#has_roles?' do
    let(:roles) do
      [
        { 'id' => 'role_1', 'key' => 'admin', 'name' => 'Administrator' },
        { 'id' => 'role_2', 'key' => 'user', 'name' => 'Standard User' }
      ]
    end
    let(:token_claims) { { 'roles' => roles } }

    context 'with matching roles' do
      it 'returns true when user has the role' do
        expect(client.has_roles?('admin')).to be true
      end

      it 'returns true when user has all specified roles' do
        expect(client.has_roles?(['admin', 'user'])).to be true
      end

      it 'accepts single role as string' do
        expect(client.has_roles?('user')).to be true
      end
    end

    context 'with non-matching roles' do
      it 'returns false when user lacks the role' do
        expect(client.has_roles?('superadmin')).to be false
      end

      it 'returns false when user lacks any of the specified roles' do
        expect(client.has_roles?(['admin', 'superadmin'])).to be false
      end
    end

    context 'with empty input' do
      it 'returns true for empty array' do
        expect(client.has_roles?([])).to be true
      end

      it 'returns true for nil' do
        expect(client.has_roles?(nil)).to be true
      end
    end

    context 'with API-based check' do
      let(:api_roles) do
        [{ 'id' => 'role_api', 'key' => 'api_role', 'name' => 'API Role' }]
      end

      before do
        stub_account_api(
          endpoint: '/roles',
          response: {
            'data' => { 'org_code' => 'org_test', 'roles' => api_roles },
            'metadata' => { 'has_more' => false }
          }
        )
      end

      it 'checks against API roles when force_api is true' do
        expect(client.has_roles?('api_role', force_api: true)).to be true
      end

      it 'returns false for token-only roles when using API' do
        expect(client.has_roles?('admin', force_api: true)).to be false
      end
    end
  end

  describe '#hasRoles' do
    it 'is an alias for has_roles?' do
      expect(client.method(:hasRoles)).to eq(client.method(:has_roles?))
    end
  end

  describe '#getRoles (PHP SDK compatible alias)' do
    let(:api_roles) do
      [{ 'id' => 'role_1', 'key' => 'admin', 'name' => 'Administrator' }]
    end

    before do
      stub_account_api(
        endpoint: '/roles',
        response: {
          'data' => { 'org_code' => 'org_test', 'roles' => api_roles },
          'metadata' => { 'has_more' => false }
        }
      )
    end

    it 'is callable' do
      expect(client).to respond_to(:getRoles)
    end

    it 'defaults to API call for PHP compatibility' do
      client.getRoles
      expect(WebMock).to have_requested(:get, /roles/)
    end
  end

  describe 'Hasura claim fallback' do
    let(:hasura_roles) do
      [
        { 'id' => 'hasura_role_1', 'key' => 'hasura_admin', 'name' => 'Hasura Admin' }
      ]
    end
    let(:token_claims) do
      {
        'roles' => nil,
        'x-hasura-roles' => hasura_roles
      }
    end

    before do
      # When roles is nil, SDK falls back to API - stub the API to return Hasura roles
      stub_account_api(
        endpoint: '/roles',
        response: {
          'data' => { 'org_code' => 'org_test', 'roles' => hasura_roles },
          'metadata' => { 'has_more' => false }
        }
      )
    end

    it 'falls back to API when roles claim is nil' do
      result = client.get_roles
      expect(result.first[:key]).to eq('hasura_admin')
    end
  end

  describe 'API error handling' do
    let(:token_roles) { [{ 'id' => 'role_1', 'key' => 'fallback', 'name' => 'Fallback' }] }
    let(:token_claims) { { 'roles' => token_roles } }

    context 'when API returns error' do
      before do
        stub_api_error(endpoint: '/roles', status: 500, error: 'Server Error')
      end

      it 'falls back to token claims gracefully' do
        result = client.get_roles(force_api: true)
        expect(result.first[:key]).to eq('fallback')
      end
    end

    context 'when API returns 401 Unauthorized' do
      before do
        stub_api_error(endpoint: '/roles', status: 401, error: 'Unauthorized')
      end

      it 'falls back to token claims' do
        result = client.get_roles(force_api: true)
        expect(result.first[:key]).to eq('fallback')
      end
    end
  end

  describe 'string-only roles handling' do
    let(:token_claims) { { 'roles' => %w[admin user] } }

    it 'handles string-only role arrays' do
      result = client.get_roles
      expect(result.length).to eq(2)
    end

    it 'converts strings to role objects' do
      result = client.get_roles
      admin = result.find { |r| r[:key] == 'admin' }
      expect(admin[:name]).to eq('admin')
      expect(admin[:id]).to be_nil
    end
  end

  describe 'without bearer token' do
    let(:tokens) { { access_token: nil } }

    before do
      stub_account_api(
        endpoint: '/roles',
        response: {
          'data' => { 'roles' => [] },
          'metadata' => { 'has_more' => false }
        }
      )
    end

    it 'returns empty array for API calls' do
      result = client.get_roles(force_api: true)
      expect(result).to eq([])
    end
  end
end
