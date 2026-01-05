# frozen_string_literal: true

require 'spec_helper'

RSpec.describe KindeSdk::TokenStore do
  describe '#initialize' do
    context 'with valid tokens' do
      let(:tokens) do
        {
          access_token: 'test_access_token',
          refresh_token: 'test_refresh_token',
          expires_at: Time.now.to_i + 3600
        }
      end

      subject(:store) { described_class.new(tokens) }

      it 'stores the tokens' do
        expect(store.tokens).to include(:access_token, :refresh_token, :expires_at)
      end

      it 'sets the bearer token' do
        expect(store.bearer_token).to eq('test_access_token')
      end

      it 'sets the expiration time' do
        expect(store.expires_at).to eq(tokens[:expires_at])
      end
    end

    context 'with string keys' do
      let(:tokens) do
        {
          'access_token' => 'string_key_token',
          'refresh_token' => 'string_refresh',
          'expires_at' => Time.now.to_i + 3600
        }
      end

      subject(:store) { described_class.new(tokens) }

      it 'converts keys to symbols' do
        expect(store.tokens.keys).to all(be_a(Symbol))
      end

      it 'extracts bearer token correctly' do
        expect(store.bearer_token).to eq('string_key_token')
      end
    end

    context 'without tokens' do
      subject(:store) { described_class.new(nil) }

      it 'does not raise an error' do
        expect { store }.not_to raise_error
      end

      it 'has nil bearer token' do
        expect(store.bearer_token).to be_nil
      end
    end
  end

  describe '#set_tokens' do
    subject(:store) { described_class.new(nil) }

    context 'updating with new tokens' do
      let(:new_tokens) do
        {
          access_token: 'new_access_token',
          refresh_token: 'new_refresh_token',
          expires_at: Time.now.to_i + 7200
        }
      end

      before { store.set_tokens(new_tokens) }

      it 'updates the bearer token' do
        expect(store.bearer_token).to eq('new_access_token')
      end

      it 'updates the expiration time' do
        expect(store.expires_at).to eq(new_tokens[:expires_at])
      end

      it 'stores all token fields' do
        expect(store.tokens[:refresh_token]).to eq('new_refresh_token')
      end
    end

    context 'clearing tokens with nil' do
      before do
        store.set_tokens(access_token: 'initial_token')
        store.set_tokens(nil)
      end

      it 'clears the bearer token' do
        expect(store.bearer_token).to be_nil
      end

      it 'has empty tokens hash' do
        expect(store.tokens).to be_empty
      end
    end

    context 'with mixed key types' do
      let(:mixed_tokens) do
        {
          'access_token' => 'mixed_token',
          refresh_token: 'symbol_refresh'
        }
      end

      before { store.set_tokens(mixed_tokens) }

      it 'normalizes all keys to symbols' do
        expect(store.tokens.keys).to all(be_a(Symbol))
      end
    end
  end

  describe '#to_session' do
    let(:tokens) do
      {
        access_token: 'session_access_token',
        refresh_token: 'session_refresh_token',
        expires_at: Time.now.to_i + 3600,
        extra_field: 'should_not_appear'
      }
    end

    subject(:store) { described_class.new(tokens) }

    it 'returns a hash suitable for session storage' do
      result = store.to_session
      expect(result).to be_a(Hash)
    end

    it 'includes the access token' do
      expect(store.to_session[:access_token]).to eq('session_access_token')
    end

    it 'includes the refresh token' do
      expect(store.to_session[:refresh_token]).to eq('session_refresh_token')
    end

    it 'includes the expiration time' do
      expect(store.to_session[:expires_at]).to eq(tokens[:expires_at])
    end

    it 'excludes extra fields' do
      expect(store.to_session).not_to have_key(:extra_field)
    end
  end

  describe '.from_session' do
    context 'with valid session data' do
      let(:session_data) do
        {
          access_token: 'from_session_token',
          refresh_token: 'from_session_refresh',
          expires_at: Time.now.to_i + 3600
        }
      end

      subject(:store) { described_class.from_session(session_data) }

      it 'creates a new token store' do
        expect(store).to be_a(described_class)
      end

      it 'populates tokens from session data' do
        expect(store.bearer_token).to eq('from_session_token')
      end
    end

    context 'with nil session data' do
      it 'returns nil' do
        expect(described_class.from_session(nil)).to be_nil
      end
    end

    context 'with empty session data' do
      it 'creates an empty store' do
        store = described_class.from_session({})
        expect(store.bearer_token).to be_nil
      end
    end
  end

  describe 'roundtrip serialization' do
    let(:original_tokens) do
      {
        access_token: 'roundtrip_access',
        refresh_token: 'roundtrip_refresh',
        expires_at: Time.now.to_i + 3600
      }
    end

    it 'preserves data through to_session and from_session' do
      original_store = described_class.new(original_tokens)
      session_data = original_store.to_session
      restored_store = described_class.from_session(session_data)

      expect(restored_store.bearer_token).to eq(original_store.bearer_token)
      expect(restored_store.tokens[:refresh_token]).to eq(original_store.tokens[:refresh_token])
      expect(restored_store.expires_at).to eq(original_store.expires_at)
    end
  end
end

