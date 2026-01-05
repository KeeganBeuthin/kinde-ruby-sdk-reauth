# frozen_string_literal: true

require 'spec_helper'

RSpec.describe KindeSdk::Current do
  after(:each) do
    described_class.clear_session
  end

  describe 'attributes' do
    it 'has a session attribute' do
      expect(described_class).to respond_to(:session)
      expect(described_class).to respond_to(:session=)
    end

    it 'has a token_store attribute' do
      expect(described_class).to respond_to(:token_store)
      expect(described_class).to respond_to(:token_store=)
    end
  end

  describe '.set_session' do
    let(:session) { { kinde_token_store: token_data } }
    let(:token_data) do
      {
        access_token: 'test_access_token',
        refresh_token: 'test_refresh_token',
        expires_at: Time.now.to_i + 3600
      }
    end

    it 'sets the session attribute' do
      described_class.set_session(session)
      expect(described_class.session).to eq(session)
    end

    context 'when session contains token store data' do
      it 'creates a token store from session data' do
        described_class.set_session(session)
        expect(described_class.token_store).to be_a(KindeSdk::TokenStore)
      end

      it 'populates token store with session data' do
        described_class.set_session(session)
        expect(described_class.token_store.bearer_token).to eq('test_access_token')
      end
    end

    context 'when session has no token store data' do
      let(:session) { {} }

      it 'does not create a token store' do
        described_class.set_session(session)
        expect(described_class.token_store).to be_nil
      end
    end

    context 'when session has nil token store' do
      let(:session) { { kinde_token_store: nil } }

      it 'does not create a token store' do
        described_class.set_session(session)
        expect(described_class.token_store).to be_nil
      end
    end
  end

  describe '.clear_session' do
    before do
      described_class.set_session({ kinde_token_store: { access_token: 'token' } })
    end

    it 'clears the session' do
      described_class.clear_session
      expect(described_class.session).to be_nil
    end

    it 'clears the token store' do
      described_class.clear_session
      expect(described_class.token_store).to be_nil
    end
  end

  describe 'thread isolation' do
    it 'isolates session between threads' do
      described_class.set_session({ thread: 'main' })

      thread_session = nil
      Thread.new do
        described_class.set_session({ thread: 'child' })
        thread_session = described_class.session
      end.join

      expect(described_class.session[:thread]).to eq('main')
      expect(thread_session[:thread]).to eq('child')
    end
  end

  describe 'request lifecycle' do
    it 'provides clean state for each request cycle' do
      # Simulate first request
      described_class.set_session({ request: 'first' })
      expect(described_class.session[:request]).to eq('first')
      described_class.clear_session

      # Simulate second request
      described_class.set_session({ request: 'second' })
      expect(described_class.session[:request]).to eq('second')
    end
  end
end

