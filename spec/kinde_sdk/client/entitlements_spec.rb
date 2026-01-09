# frozen_string_literal: true

require 'spec_helper'

RSpec.describe KindeSdk::Client::Entitlements do
  include_context 'authenticated client'

  let(:entitlements_response) do
    {
      'data' => {
        'org_code' => 'org_test123',
        'plans' => [
          { 'key' => 'pro_plan', 'subscribed_on' => '2024-01-01T00:00:00Z' }
        ],
        'entitlements' => entitlements
      },
      'metadata' => { 'has_more' => false }
    }
  end

  let(:entitlements) do
    [
      {
        'id' => 'ent_1',
        'feature_key' => 'advanced_reports',
        'feature_name' => 'Advanced Reports',
        'price_name' => 'Pro Plan',
        'fixed_charge' => 50,
        'unit_amount' => 1,
        'entitlement_limit_max' => 100,
        'entitlement_limit_min' => 1
      },
      {
        'id' => 'ent_2',
        'feature_key' => 'api_access',
        'feature_name' => 'API Access',
        'price_name' => 'Enterprise',
        'fixed_charge' => 100,
        'unit_amount' => 1,
        'entitlement_limit_max' => 1000,
        'entitlement_limit_min' => 1
      },
      {
        'id' => 'ent_3',
        'feature_key' => 'premium_support',
        'feature_name' => 'Premium Support',
        'price_name' => 'Pro Plan',
        'fixed_charge' => 25,
        'unit_amount' => 1,
        'entitlement_limit_max' => nil,
        'entitlement_limit_min' => nil
      }
    ]
  end

  before do
    stub_account_api(
      endpoint: '/entitlements',
      response: entitlements_response
    )
  end

  describe '#get_entitlements' do
    it 'retrieves entitlements from API' do
      result = client.get_entitlements
      expect(result.length).to eq(3)
    end

    it 'includes all entitlement data' do
      result = client.get_entitlements
      advanced = result.find { |e| e.respond_to?(:feature_key) ? e.feature_key == 'advanced_reports' : e['feature_key'] == 'advanced_reports' }
      expect(advanced).not_to be_nil
    end
  end

  describe '#getAllEntitlements' do
    it 'returns all entitlements' do
      result = client.getAllEntitlements
      expect(result.length).to eq(3)
    end


    context 'without bearer token' do
      let(:tokens) { { access_token: nil } }

      it 'raises authentication error' do
        expect { client.getAllEntitlements }.to raise_error(KindeSdk::APIError)
      end
    end
  end

  describe '#all_entitlements (Ruby alias)' do
    it 'is an alias for getAllEntitlements' do
      expect(client.method(:all_entitlements)).to eq(client.method(:getAllEntitlements))
    end
  end

  describe '#entitlement' do
    before do
      stub_account_api(
        endpoint: '/entitlement',
        response: {
          'data' => {
            'entitlement' => entitlements.first
          }
        }
      )
    end

    it 'retrieves a specific entitlement by key' do
      result = client.entitlement('advanced_reports')
      expect(result).not_to be_nil
    end
  end

  describe '#getEntitlement (PHP SDK compatible alias)' do
    it 'finds entitlement from all entitlements' do
      result = client.getEntitlement('advanced_reports')
      key = result.respond_to?(:feature_key) ? result.feature_key : result['feature_key']
      expect(key).to eq('advanced_reports')
    end

    it 'returns nil for non-existent entitlement' do
      result = client.getEntitlement('non_existent')
      expect(result).to be_nil
    end
  end

  describe '#has_entitlement?' do
    before do
      stub_account_api(
        endpoint: '/entitlement',
        response: {
          'data' => {
            'entitlement' => entitlements.first
          }
        }
      )
    end

    it 'returns true when user has the entitlement' do
      allow(client).to receive(:entitlement).and_return(
        OpenStruct.new(data: OpenStruct.new(entitlement: entitlements.first))
      )
      expect(client.has_entitlement?('advanced_reports')).to be true
    end

    context 'when entitlement does not exist' do
      before do
        stub_api_error(endpoint: '/entitlement', status: 404)
      end

      it 'returns false' do
        allow(client).to receive(:entitlement).and_return(nil)
        expect(client.has_entitlement?('non_existent')).to be false
      end
    end
  end

  describe '#hasEntitlement (PHP SDK compatible alias)' do
    it 'returns true when entitlement exists' do
      result = client.hasEntitlement('advanced_reports')
      expect(result).to be true
    end

    it 'returns false when entitlement does not exist' do
      result = client.hasEntitlement('non_existent')
      expect(result).to be false
    end
  end

  describe '#getEntitlementLimit' do
    it 'returns the maximum limit for an entitlement' do
      result = client.getEntitlementLimit('advanced_reports')
      expect(result).to eq(100)
    end

    it 'returns nil for entitlement without limit' do
      result = client.getEntitlementLimit('premium_support')
      expect(result).to be_nil
    end

    it 'returns nil for non-existent entitlement' do
      result = client.getEntitlementLimit('non_existent')
      expect(result).to be_nil
    end
  end

  describe '#entitlement_limit (Ruby alias)' do
    it 'is an alias for getEntitlementLimit' do
      expect(client.method(:entitlement_limit)).to eq(client.method(:getEntitlementLimit))
    end
  end

  describe '#has_billing_entitlements?' do
    context 'with matching billing entitlements' do
      it 'returns true when user has all specified billing entitlements' do
        expect(client.has_billing_entitlements?(['Pro Plan'])).to be true
      end

      it 'returns true for multiple matching entitlements' do
        expect(client.has_billing_entitlements?(['Pro Plan', 'Enterprise'])).to be true
      end
    end

    context 'with missing billing entitlements' do
      it 'returns false when user is missing a billing entitlement' do
        expect(client.has_billing_entitlements?(['Non-existent Plan'])).to be false
      end

      it 'returns false when any entitlement is missing' do
        expect(client.has_billing_entitlements?(['Pro Plan', 'Non-existent'])).to be false
      end
    end

    context 'with empty input' do
      it 'returns true for nil' do
        expect(client.has_billing_entitlements?(nil)).to be true
      end

      it 'returns true for empty array' do
        expect(client.has_billing_entitlements?([])).to be true
      end
    end
  end

  describe '#hasBillingEntitlements (alias)' do
    it 'is an alias for has_billing_entitlements?' do
      expect(client.method(:hasBillingEntitlements)).to eq(client.method(:has_billing_entitlements?))
    end
  end

  describe '#has_entitlements?' do
    context 'with matching feature entitlements' do
      it 'returns true when user has all specified entitlements' do
        expect(client.has_entitlements?(['advanced_reports'])).to be true
      end

      it 'returns true for multiple matching entitlements' do
        expect(client.has_entitlements?(['advanced_reports', 'api_access'])).to be true
      end
    end

    context 'with missing feature entitlements' do
      it 'returns false when user is missing an entitlement' do
        expect(client.has_entitlements?(['non_existent_feature'])).to be false
      end

      it 'returns false when any entitlement is missing' do
        expect(client.has_entitlements?(['advanced_reports', 'missing'])).to be false
      end
    end

    context 'with empty input' do
      it 'returns true for nil' do
        expect(client.has_entitlements?(nil)).to be true
      end

      it 'returns true for empty array' do
        expect(client.has_entitlements?([])).to be true
      end
    end
  end

  describe '#hasEntitlements (alias)' do
    it 'is an alias for has_entitlements?' do
      expect(client.method(:hasEntitlements)).to eq(client.method(:has_entitlements?))
    end
  end

  describe 'API error handling' do
    context 'when API returns 401 Unauthorized' do
      before do
        stub_api_error(endpoint: '/entitlements', status: 401, error: 'Unauthorized')
      end

      it 'raises APIError' do
        expect { client.getAllEntitlements }.to raise_error(KindeSdk::APIError)
      end
    end

    context 'when API returns 403 Forbidden' do
      before do
        stub_api_error(endpoint: '/entitlements', status: 403, error: 'Forbidden')
      end

      it 'raises APIError' do
        expect { client.getAllEntitlements }.to raise_error(KindeSdk::APIError)
      end
    end

    context 'when API returns 500 Server Error' do
      before do
        stub_api_error(endpoint: '/entitlements', status: 500, error: 'Server Error')
      end

      it 'raises APIError' do
        expect { client.getAllEntitlements }.to raise_error(KindeSdk::APIError)
      end
    end
  end

  describe 'empty entitlements' do
    let(:entitlements) { [] }

    it 'returns empty array' do
      result = client.getAllEntitlements
      expect(result).to eq([])
    end

    it 'has_entitlements? returns true for empty check' do
      expect(client.has_entitlements?([])).to be true
    end

    it 'has_billing_entitlements? returns true for empty check' do
      expect(client.has_billing_entitlements?([])).to be true
    end

    it 'has_entitlements? returns false for any specific entitlement' do
      expect(client.has_entitlements?(['any_feature'])).to be false
    end
  end
end

