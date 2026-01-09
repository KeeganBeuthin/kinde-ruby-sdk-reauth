# frozen_string_literal: true

require 'spec_helper'

RSpec.describe KindeSdk::Middleware do
  let(:app) { ->(env) { [200, {}, ['OK']] } }
  let(:middleware) { described_class.new(app) }

  describe '#initialize' do
    it 'stores the app reference' do
      expect(middleware.instance_variable_get(:@app)).to eq(app)
    end
  end

  describe '#call' do
    let(:session) { { kinde_token_store: { access_token: 'test_token' } } }
    let(:env) { build_mock_env(session: session) }
    let(:mock_request) { instance_double(ActionDispatch::Request, session: session) }

    before do
      allow(ActionDispatch::Request).to receive(:new).and_return(mock_request)
    end

    it 'sets the current session' do
      expect(KindeSdk::Current).to receive(:set_session).with(session)
      middleware.call(env)
    end

    it 'calls the app' do
      expect(app).to receive(:call).with(env).and_return([200, {}, ['OK']])
      middleware.call(env)
    end

    it 'returns the app response' do
      response = middleware.call(env)
      expect(response).to eq([200, {}, ['OK']])
    end

    it 'clears the session after the request' do
      expect(KindeSdk::Current).to receive(:clear_session)
      middleware.call(env)
    end

    context 'when app raises an error' do
      let(:error_app) { ->(_env) { raise StandardError, 'Test error' } }
      let(:error_middleware) { described_class.new(error_app) }

      it 'still clears the session' do
        expect(KindeSdk::Current).to receive(:clear_session)
        expect { error_middleware.call(env) }.to raise_error(StandardError, 'Test error')
      end
    end

    context 'with empty session' do
      let(:session) { {} }

      it 'handles empty session gracefully' do
        expect { middleware.call(env) }.not_to raise_error
      end
    end
  end
end



