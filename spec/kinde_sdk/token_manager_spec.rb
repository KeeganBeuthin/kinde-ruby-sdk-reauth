# frozen_string_literal: true

require 'spec_helper'

RSpec.describe KindeSdk::TokenManager do
  include_context 'configured SDK'

  let(:valid_tokens) { build_tokens }
  let(:token_store) { KindeSdk::TokenStore.new(valid_tokens) }

  describe '.create_store' do
    it 'creates a TokenStore instance' do
      store = described_class.create_store(valid_tokens)
      expect(store).to be_a(KindeSdk::TokenStore)
    end

    it 'populates the store with tokens' do
      store = described_class.create_store(valid_tokens)
      expect(store.bearer_token).to eq(valid_tokens[:access_token])
    end

    it 'handles nil tokens' do
      store = described_class.create_store(nil)
      expect(store.bearer_token).to be_nil
    end
  end

  describe '.token_expired?' do
    context 'with nil store' do
      it 'returns true' do
        expect(described_class.token_expired?(nil)).to be true
      end
    end
  end

  describe '.validate_tokens' do
    context 'with invalid JWT tokens' do
      let(:valid_tokens) { { access_token: 'not.a.valid.jwt' } }

      it 'returns false' do
        expect(described_class.validate_tokens(token_store)).to be false
      end
    end

    context 'with nil store' do
      it 'returns false' do
        expect(described_class.validate_tokens(nil)).to be false
      end
    end
  end

  describe '.clear_tokens' do
    let(:mock_session) { { kinde_token_store: { access_token: 'old_token' } } }

    before do
      token_store.set_tokens(valid_tokens)
    end

    it 'clears the store tokens' do
      described_class.clear_tokens(token_store, mock_session)
      expect(token_store.bearer_token).to be_nil
    end

    it 'removes token data from session' do
      described_class.clear_tokens(token_store, mock_session)
      expect(mock_session[:kinde_token_store]).to be_nil
    end

    context 'with nil session' do
      it 'does not raise an error' do
        expect { described_class.clear_tokens(token_store, nil) }.not_to raise_error
      end

      it 'still clears the store' do
        described_class.clear_tokens(token_store, nil)
        expect(token_store.bearer_token).to be_nil
      end
    end
  end
end
