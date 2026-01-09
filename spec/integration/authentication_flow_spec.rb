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

      it 'includes supports_reauth parameter' do
        auth = KindeSdk.auth_url
        expect(auth[:url]).to include('supports_reauth=true')
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

      it 'includes custom audience when provided' do
        auth = KindeSdk.auth_url(audience: 'https://api.example.com')
        expect(auth[:url]).to include('audience=')
      end
    end

    describe 'without PKCE' do
      before do
        KindeSdk.config.pkce_enabled = false
      end

      after do
        KindeSdk.config.pkce_enabled = true
      end

      it 'generates auth URL without PKCE parameters' do
        auth = KindeSdk.auth_url

        expect(auth).to have_key(:url)
        expect(auth).not_to have_key(:code_verifier)
        expect(auth[:url]).not_to include('code_challenge=')
      end
    end
  end

  describe 'Logout Flow' do
    describe 'with HTTPS domain' do
      it 'generates valid logout URL' do
        logout_url = KindeSdk.logout_url

        expect(logout_url).to be_a(String)
        expect(logout_url).to include('test.kinde.com')
        expect(logout_url).to include('/logout')
      end

      it 'preserves HTTPS scheme' do
        logout_url = KindeSdk.logout_url
        expect(logout_url).to start_with('https://')
      end

      it 'includes redirect parameter' do
        logout_url = KindeSdk.logout_url
        expect(logout_url).to include('redirect=')
      end

      it 'encodes the redirect URL properly' do
        logout_url = KindeSdk.logout_url
        expect(logout_url).to include(URI.encode_www_form_component(test_logout_url))
      end
    end

    describe 'with custom domain' do
      it 'uses provided domain' do
        logout_url = KindeSdk.logout_url(domain: 'https://custom.kinde.com')
        expect(logout_url).to include('custom.kinde.com')
      end

      it 'preserves HTTP scheme when explicitly provided' do
        logout_url = KindeSdk.logout_url(domain: 'http://localhost:3000')
        expect(logout_url).to start_with('http://')
        expect(logout_url).to include('localhost:3000')
      end

      it 'defaults to HTTPS when no scheme provided' do
        logout_url = KindeSdk.logout_url(domain: 'example.kinde.com')
        expect(logout_url).to start_with('https://')
      end

      it 'preserves non-standard ports' do
        logout_url = KindeSdk.logout_url(domain: 'https://localhost:8443')
        expect(logout_url).to include('localhost:8443')
      end

      it 'omits default HTTPS port' do
        logout_url = KindeSdk.logout_url(domain: 'https://example.com:443')
        expect(logout_url).not_to include(':443')
      end

      it 'omits default HTTP port' do
        logout_url = KindeSdk.logout_url(domain: 'http://example.com:80')
        expect(logout_url).not_to include(':80')
      end
    end

    describe 'domain validation' do
      it 'raises error for nil domain' do
        expect { KindeSdk.logout_url(domain: nil) }
          .to raise_error(ArgumentError, /domain is required/)
      end

      it 'raises error for empty domain' do
        expect { KindeSdk.logout_url(domain: '') }
          .to raise_error(ArgumentError, /domain is required/)
      end

      it 'raises error for whitespace-only domain' do
        expect { KindeSdk.logout_url(domain: '   ') }
          .to raise_error(ArgumentError, /domain is required/)
      end

      it 'raises error for invalid scheme' do
        expect { KindeSdk.logout_url(domain: 'ftp://example.com') }
          .to raise_error(ArgumentError, /invalid scheme.*only http\/https allowed/)
      end

      it 'raises error for file scheme' do
        expect { KindeSdk.logout_url(domain: 'file:///etc/passwd') }
          .to raise_error(ArgumentError, /invalid scheme.*only http\/https allowed/)
      end
    end

    describe 'with custom logout URL' do
      it 'uses provided logout redirect URL' do
        logout_url = KindeSdk.logout_url(logout_url: 'https://app.example.com/logged-out')
        expect(logout_url).to include(URI.encode_www_form_component('https://app.example.com/logged-out'))
      end

      it 'handles nil logout URL' do
        logout_url = KindeSdk.logout_url(logout_url: nil)
        expect(logout_url).not_to include('redirect=')
      end
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

    context 'with valid token structure' do
      let(:valid_token) { generate_access_token }

      it 'can decode token payload' do
        payload = decode_token_payload(valid_token)
        expect(payload).to have_key('sub')
        expect(payload).to have_key('exp')
        expect(payload).to have_key('iss')
      end
    end
  end

  describe 'Client Credentials Flow' do
    let(:m2m_tokens) do
      {
        'access_token' => generate_access_token,
        'token_type' => 'bearer',
        'expires_in' => 3600
      }
    end

    it 'exchanges client credentials for access token' do
      # Mock Faraday to intercept the HTTP call
      mock_response = instance_double(Faraday::Response, body: m2m_tokens)
      mock_connection = instance_double(Faraday::Connection)

      allow(Faraday).to receive(:new).and_return(mock_connection)
      allow(mock_connection).to receive(:post).and_return(mock_response)

      result = KindeSdk.client_credentials_access

      expect(result).to have_key('access_token')
      expect(result['token_type']).to eq('bearer')
    end
  end

  describe 'Token Refresh' do
    let(:new_access_token) { generate_access_token }
    let(:new_refresh_token) { generate_refresh_token }
    let(:new_expires_at) { Time.now.to_i + 3600 }

    it 'refreshes expired tokens' do
      old_tokens = {
        access_token: generate_expired_token,
        refresh_token: generate_refresh_token,
        expires_at: Time.now.to_i - 3600
      }

      # Mock the OAuth2::AccessToken refresh cycle
      mock_oauth_token = instance_double(
        OAuth2::AccessToken,
        token: new_access_token,
        refresh_token: new_refresh_token,
        expires_at: new_expires_at,
        params: { 'id_token' => generate_id_token }
      )

      mock_refreshed = instance_double(
        OAuth2::AccessToken,
        to_hash: {
          access_token: new_access_token,
          refresh_token: new_refresh_token,
          expires_at: new_expires_at
        }
      )

      allow(OAuth2::AccessToken).to receive(:from_hash).and_return(mock_oauth_token)
      allow(mock_oauth_token).to receive(:refresh).and_return(mock_refreshed)

      result = KindeSdk.refresh_token(old_tokens)
      expect(result).to have_key(:access_token)
    end
  end
end
