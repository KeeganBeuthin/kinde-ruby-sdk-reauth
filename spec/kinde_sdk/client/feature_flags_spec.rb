# frozen_string_literal: true

require 'spec_helper'

RSpec.describe KindeSdk::Client::FeatureFlags do
  include_context 'authenticated client'

  let(:feature_flags) do
    {
      'dark_mode' => { 't' => 'b', 'v' => true },
      'max_items' => { 't' => 'i', 'v' => 100 },
      'theme' => { 't' => 's', 'v' => 'modern' },
      'beta_feature' => { 't' => 'b', 'v' => false },
      'disabled_feature' => { 't' => 'b', 'v' => false }
    }
  end
  let(:token_claims) { { 'feature_flags' => feature_flags } }

  describe '#get_flags' do
    context 'soft check (token-based)' do
      it 'extracts flags from token claims' do
        flags = client.get_flags
        expect(flags.length).to eq(5)
      end

      it 'returns flags with correct structure' do
        flags = client.get_flags
        dark_mode = flags.find { |f| f[:key] == 'dark_mode' }

        expect(dark_mode).to include(
          key: 'dark_mode',
          value: true,
          type: 'boolean'
        )
      end

      it 'converts boolean type codes correctly' do
        flags = client.get_flags
        dark_mode = flags.find { |f| f[:key] == 'dark_mode' }
        expect(dark_mode[:type]).to eq('boolean')
      end

      it 'converts integer type codes correctly' do
        flags = client.get_flags
        max_items = flags.find { |f| f[:key] == 'max_items' }
        expect(max_items[:type]).to eq('integer')
        expect(max_items[:value]).to eq(100)
      end

      it 'converts string type codes correctly' do
        flags = client.get_flags
        theme = flags.find { |f| f[:key] == 'theme' }
        expect(theme[:type]).to eq('string')
        expect(theme[:value]).to eq('modern')
      end

      it 'does not make API calls' do
        client.get_flags
        expect(WebMock).not_to have_requested(:get, /account_api/)
      end
    end

    context 'with empty feature flags' do
      let(:token_claims) { { 'feature_flags' => {} } }

      it 'returns empty array' do
        expect(client.get_flags).to eq([])
      end
    end

    context 'with nil feature flags' do
      let(:token_claims) { { 'feature_flags' => nil } }

      it 'returns empty array' do
        expect(client.get_flags).to eq([])
      end
    end

    context 'with missing feature flags claim' do
      let(:token_claims) { {} }

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

      it 'returns empty array' do
        expect(client.get_flags).to eq([])
      end
    end

    context 'hard check (API-based)' do
      let(:api_flags) do
        [
          { 'key' => 'api_flag', 'value' => true, 'type' => 'boolean' },
          { 'key' => 'another_flag', 'value' => 'value', 'type' => 'string' }
        ]
      end

      before do
        stub_account_api(
          endpoint: '/feature_flags',
          response: build_paginated_response(
            data_key: 'feature_flags',
            items: api_flags,
            has_more: false
          )
        )
      end

      it 'fetches flags from API when force_api is true' do
        client.get_flags(force_api: true)
        expect(WebMock).to have_requested(:get, /feature_flags/)
      end

      it 'returns API flags instead of token flags' do
        flags = client.get_flags(force_api: true)
        flag_keys = flags.map { |f| f[:key] }
        expect(flag_keys).to include('api_flag', 'another_flag')
        expect(flag_keys).not_to include('dark_mode')
      end
    end

    context 'legacy positional argument' do
      it 'accepts token_type as positional argument' do
        flags = client.get_flags(:access_token)
        expect(flags.length).to eq(5)
      end
    end
  end

  describe '#get_flag' do
    context 'with existing flag' do
      it 'returns the flag value and metadata' do
        flag = client.get_flag('dark_mode')
        expect(flag).to include(
          code: 'dark_mode',
          type: 'boolean',
          value: true,
          is_default: false
        )
      end

      it 'returns boolean true flag values' do
        flag = client.get_flag('dark_mode')
        expect(flag[:value]).to be true
      end

      # Critical test for PR #74 fix - boolean false handling with key?
      it 'returns boolean false flag values correctly' do
        flag = client.get_flag('beta_feature')
        expect(flag[:value]).to be false
      end

      it 'returns integer flag values' do
        flag = client.get_flag('max_items')
        expect(flag[:value]).to eq(100)
      end

      it 'returns string flag values' do
        flag = client.get_flag('theme')
        expect(flag[:value]).to eq('modern')
      end

      it 'distinguishes between false and nil' do
        flag = client.get_flag('disabled_feature')
        expect(flag[:value]).to eq(false)
        expect(flag[:value]).not_to be_nil
      end
    end

    context 'with non-existent flag' do
      it 'returns nil without default value' do
        flag = client.get_flag('non_existent')
        expect(flag).to be_nil
      end
    end

    context 'with API-based retrieval' do
      let(:api_flags) do
        [{ 'key' => 'api_only_flag', 'value' => 'api_value', 'type' => 'string' }]
      end

      before do
        stub_account_api(
          endpoint: '/feature_flags',
          response: build_paginated_response(
            data_key: 'feature_flags',
            items: api_flags,
            has_more: false
          )
        )
      end

      it 'fetches from API when force_api is true' do
        flag = client.get_flag('api_only_flag', force_api: true)
        expect(flag[:value]).to eq('api_value')
      end
    end
  end

  describe '#get_flag (legacy 3-parameter signature)' do
    context 'with existing flag' do
      it 'returns flag with metadata' do
        flag = client.get_flag('dark_mode', {}, nil)
        expect(flag[:value]).to be true
        expect(flag[:is_default]).to be false
      end
    end

    context 'with default value for missing flag' do
      it 'returns the default value' do
        flag = client.get_flag('missing_flag', { default_value: 'default' }, nil)
        expect(flag[:value]).to eq('default')
        expect(flag[:is_default]).to be true
      end

      it 'raises error when no default and flag missing' do
        expect { client.get_flag('missing_flag', {}, 'b') }
          .to raise_error(StandardError, /not found.*no default/)
      end
    end

    context 'with type validation' do
      it 'raises error when default type mismatches requested type' do
        expect { client.get_flag('missing', { default_value: true }, 's') }
          .to raise_error(ArgumentError, /different from requested type/)
      end

      it 'accepts matching default types' do
        flag = client.get_flag('missing', { default_value: true }, 'b')
        expect(flag[:value]).to be true
      end
    end
  end

  describe '#get_boolean_flag' do
    it 'returns boolean true flag value' do
      expect(client.get_boolean_flag('dark_mode')).to be true
    end

    # Critical test for PR #74 fix
    it 'returns boolean false flag value correctly' do
      expect(client.get_boolean_flag('beta_feature')).to be false
    end

    it 'returns false boolean correctly (not nil)' do
      result = client.get_boolean_flag('disabled_feature')
      expect(result).to eq(false)
      expect(result).not_to be_nil
    end

    it 'raises error for non-boolean flag' do
      expect { client.get_boolean_flag('max_items') }
        .to raise_error(ArgumentError, /different from requested type/)
    end

    it 'returns default value for missing flag' do
      expect(client.get_boolean_flag('missing', false)).to be false
    end

    it 'returns true default value for missing flag' do
      expect(client.get_boolean_flag('missing', true)).to be true
    end
  end

  describe '#get_integer_flag' do
    it 'returns integer flag value' do
      expect(client.get_integer_flag('max_items')).to eq(100)
    end

    it 'raises error for non-integer flag' do
      expect { client.get_integer_flag('dark_mode') }
        .to raise_error(ArgumentError, /different from requested type/)
    end

    it 'returns default value for missing flag' do
      expect(client.get_integer_flag('missing', 50)).to eq(50)
    end

    it 'returns zero default value for missing flag' do
      expect(client.get_integer_flag('missing', 0)).to eq(0)
    end
  end

  describe '#get_string_flag' do
    it 'returns string flag value' do
      expect(client.get_string_flag('theme')).to eq('modern')
    end

    it 'raises error for non-string flag' do
      expect { client.get_string_flag('dark_mode') }
        .to raise_error(ArgumentError, /different from requested type/)
    end

    it 'returns default value for missing flag' do
      expect(client.get_string_flag('missing', 'default')).to eq('default')
    end

    it 'returns empty string default value for missing flag' do
      expect(client.get_string_flag('missing', '')).to eq('')
    end
  end

  describe '#has_feature_flags?' do
    context 'with string flag names' do
      it 'returns true when user has all flags' do
        expect(client.has_feature_flags?(['dark_mode', 'theme'])).to be true
      end

      it 'returns false when user missing flags' do
        expect(client.has_feature_flags?(['dark_mode', 'non_existent'])).to be false
      end

      it 'returns true for empty array' do
        expect(client.has_feature_flags?([])).to be true
      end

      it 'returns true for nil' do
        expect(client.has_feature_flags?(nil)).to be true
      end
    end

    context 'with flag conditions' do
      it 'returns true when flag matches condition value' do
        conditions = [{ flag: 'dark_mode', value: true }]
        expect(client.has_feature_flags?(conditions)).to be true
      end

      it 'returns false when flag value does not match' do
        conditions = [{ flag: 'dark_mode', value: false }]
        expect(client.has_feature_flags?(conditions)).to be false
      end

      # Critical test for PR #74 fix - checking false values
      it 'correctly checks false boolean conditions' do
        conditions = [{ flag: 'beta_feature', value: false }]
        expect(client.has_feature_flags?(conditions)).to be true
      end

      it 'checks integer values correctly' do
        conditions = [{ flag: 'max_items', value: 100 }]
        expect(client.has_feature_flags?(conditions)).to be true
      end

      it 'checks string values correctly' do
        conditions = [{ flag: 'theme', value: 'modern' }]
        expect(client.has_feature_flags?(conditions)).to be true
      end

      it 'returns false for wrong integer value' do
        conditions = [{ flag: 'max_items', value: 50 }]
        expect(client.has_feature_flags?(conditions)).to be false
      end

      it 'returns false for wrong string value' do
        conditions = [{ flag: 'theme', value: 'classic' }]
        expect(client.has_feature_flags?(conditions)).to be false
      end
    end
  end

  describe '#getFlags (alias)' do
    it 'is callable' do
      expect(client).to respond_to(:getFlags)
    end
  end

  describe '#hasFeatureFlags (alias)' do
    it 'is an alias for has_feature_flags?' do
      expect(client.method(:hasFeatureFlags)).to eq(client.method(:has_feature_flags?))
    end
  end

  describe 'Hasura claim fallback' do
    let(:token_claims) do
      {
        'feature_flags' => nil,
        'x-hasura-feature-flags' => feature_flags
      }
    end

    it 'falls back to x-hasura-feature-flags claim' do
      flags = client.get_flags
      expect(flags.length).to eq(5)
    end

    it 'correctly extracts values from hasura claims' do
      flags = client.get_flags
      dark_mode = flags.find { |f| f[:key] == 'dark_mode' }
      expect(dark_mode[:value]).to be true
    end
  end

  describe 'API error handling' do
    let(:token_claims) { {} }

    context 'when API returns error' do
      before do
        stub_api_error(endpoint: '/feature_flags', status: 500, error: 'Server Error')
      end

      it 'falls back to token claims gracefully' do
        expect { client.get_flags(force_api: true) }.not_to raise_error
      end

      it 'returns empty array on fallback with no token claims' do
        result = client.get_flags(force_api: true)
        expect(result).to eq([])
      end
    end

    context 'when API returns 401 Unauthorized' do
      before do
        stub_api_error(endpoint: '/feature_flags', status: 401, error: 'Unauthorized')
      end

      it 'falls back gracefully' do
        expect { client.get_flags(force_api: true) }.not_to raise_error
      end
    end
  end

  describe 'flag type mapping' do
    let(:feature_flags) do
      {
        'bool_flag' => { 't' => 'b', 'v' => true },
        'string_flag' => { 't' => 's', 'v' => 'test' },
        'int_flag' => { 't' => 'i', 'v' => 42 },
        'object_flag' => { 't' => 'o', 'v' => { 'nested' => 'value' } },
        'unknown_flag' => { 't' => 'x', 'v' => 'unknown' }
      }
    end

    it 'maps "b" to "boolean"' do
      flags = client.get_flags
      flag = flags.find { |f| f[:key] == 'bool_flag' }
      expect(flag[:type]).to eq('boolean')
    end

    it 'maps "s" to "string"' do
      flags = client.get_flags
      flag = flags.find { |f| f[:key] == 'string_flag' }
      expect(flag[:type]).to eq('string')
    end

    it 'maps "i" to "integer"' do
      flags = client.get_flags
      flag = flags.find { |f| f[:key] == 'int_flag' }
      expect(flag[:type]).to eq('integer')
    end

    it 'maps "o" to "object"' do
      flags = client.get_flags
      flag = flags.find { |f| f[:key] == 'object_flag' }
      expect(flag[:type]).to eq('object')
    end

    it 'defaults unknown types to "string"' do
      flags = client.get_flags
      flag = flags.find { |f| f[:key] == 'unknown_flag' }
      expect(flag[:type]).to eq('string')
    end
  end
end
