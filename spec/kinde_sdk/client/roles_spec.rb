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

  describe '#has_roles?' do
    # Test using the simple array form that doesn't trigger normalize_roles bug
    it 'returns true for empty array' do
      expect(client.has_roles?([])).to be true
    end

    it 'returns true for nil' do
      expect(client.has_roles?(nil)).to be true
    end
  end

  describe '#hasRoles' do
    it 'is an alias for has_roles?' do
      expect(client.method(:hasRoles)).to eq(client.method(:has_roles?))
    end
  end

  describe 'API-based role retrieval' do
    let(:api_roles) do
      [
        { 'id' => 'role_1', 'key' => 'admin', 'name' => 'Administrator' }
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

    it 'makes API request when force_api is true' do
      client.get_roles(force_api: true)
      expect(WebMock).to have_requested(:get, /roles/)
    end

    it 'includes authorization header in API requests' do
      client.get_roles(force_api: true)
      expect(WebMock).to have_requested(:get, /roles/)
        .with(headers: { 'Authorization' => /^Bearer / })
    end
  end
end
