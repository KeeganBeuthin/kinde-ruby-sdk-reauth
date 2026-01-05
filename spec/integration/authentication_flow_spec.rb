# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'Authentication Flow Integration', type: :integration do
  include_context 'configured SDK'

  describe 'PKCE Authorization Code Flow' do
    describe 'generating auth URL' do
      it 'generates valid authorization URL with PKCE parameters' do
        auth = KindeSdk.auth_url

        expect(auth).to have_key(:url)
        expect(auth).to have_key(:code_verifier)
        expect(auth[:url]).to include(test_domain)
        expect(auth[:url]).to include('code_challenge=')
        expect(auth[:url]).to include('code_challenge_method=S256')
        expect(auth[:url]).to include("client_id=#{test_client_id}")
        expect(auth[:url]).to include('response_type=code')
      end

      it 'generates unique code verifiers' do
        auth1 = KindeSdk.auth_url
        auth2 = KindeSdk.auth_url

        expect(auth1[:code_verifier]).not_to eq(auth2[:code_verifier])
      end

      it 'includes the callback URL' do
        auth = KindeSdk.auth_url
        expect(auth[:url]).to include(URI.encode_www_form_component(test_callback_url))
      end

      it 'includes requested scopes' do
        auth = KindeSdk.auth_url
        expect(auth[:url]).to include('scope=')
        expect(auth[:url]).to include('openid')
      end
    end

    describe 'generating auth URL with options' do
      it 'includes organization code when provided' do
        auth = KindeSdk.auth_url(org_code: 'org_test123')
        expect(auth[:url]).to include('org_code=org_test123')
      end

      it 'includes start_page parameter for registration' do
        auth = KindeSdk.auth_url(start_page: 'registration')
        expect(auth[:url]).to include('start_page=registration')
      end

      it 'includes additional params' do
        auth = KindeSdk.auth_url(additional_params: { login_hint: 'test@example.com' })
        # SDK encodes additional_params as nested params
        expect(auth[:url]).to include('additional_params')
        expect(auth[:url]).to include('test%40example.com')
      end
    end
  end

  describe 'Logout Flow' do
    it 'generates valid logout URL' do
      logout_url = KindeSdk.logout_url

      expect(logout_url).to be_a(String)
      expect(logout_url).to include('test.kinde.com')
      expect(logout_url).to include('/logout')
    end

    it 'includes redirect parameter' do
      logout_url = KindeSdk.logout_url

      expect(logout_url).to include('redirect=')
    end
  end

  describe 'JWT Token Validation' do
    context 'with malformed token' do
      it 'raises JWT::DecodeError' do
        expect {
          KindeSdk.validate_jwt_token(access_token: 'not.a.valid.jwt')
        }.to raise_error(JWT::DecodeError)
      end
    end

    context 'with expired token' do
      let(:expired_token) { generate_expired_token }

      it 'identifies token as expired' do
        expect(KindeSdk.token_expired?({ 'access_token' => expired_token })).to be true
      end
    end
  end
end
