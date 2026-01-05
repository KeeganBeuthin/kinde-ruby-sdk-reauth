# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'Token Refresh Integration', type: :integration do
  include_context 'configured SDK'

  describe 'Auto-refresh disabled' do
    let(:expired_tokens) { build_expired_tokens }

    it 'does not refresh when auto_refresh is disabled' do
      client = KindeSdk.client(expired_tokens, false)
      # Token stays the same - no refresh attempted
      expect(client.bearer_token).to eq(expired_tokens[:access_token])
    end
  end

  describe 'Token Expiration Detection' do
    it 'delegates to TokenManager' do
      tokens = build_tokens
      client = KindeSdk.client(tokens, false)

      allow(KindeSdk::TokenManager).to receive(:token_expired?).and_return(true)
      expect(client.token_expired?).to be true

      allow(KindeSdk::TokenManager).to receive(:token_expired?).and_return(false)
      expect(client.token_expired?).to be false
    end
  end
end
