# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'KindeSdk Errors' do
  describe KindeSdk::Error do
    it 'inherits from StandardError' do
      expect(described_class.superclass).to eq(StandardError)
    end

    it 'can be raised with a message' do
      expect { raise described_class, 'Test error' }
        .to raise_error(described_class, 'Test error')
    end

    it 'can be rescued as StandardError' do
      rescued = false
      begin
        raise described_class, 'Test'
      rescue StandardError
        rescued = true
      end
      expect(rescued).to be true
    end
  end

  describe KindeSdk::APIError do
    it 'inherits from KindeSdk::Error' do
      expect(described_class.superclass).to eq(KindeSdk::Error)
    end

    it 'can be raised with a message' do
      expect { raise described_class, 'API request failed' }
        .to raise_error(described_class, 'API request failed')
    end

    it 'can be rescued as KindeSdk::Error' do
      rescued_as_kinde_error = false
      begin
        raise described_class, 'API Error'
      rescue KindeSdk::Error
        rescued_as_kinde_error = true
      end
      expect(rescued_as_kinde_error).to be true
    end
  end

  describe KindeSdk::AuthenticationError do
    it 'inherits from APIError' do
      expect(described_class.superclass).to eq(KindeSdk::APIError)
    end

    it 'represents 401 unauthorized errors' do
      error = described_class.new('Invalid or expired token')
      expect(error.message).to eq('Invalid or expired token')
    end

    it 'can be rescued as APIError' do
      rescued_as_api_error = false
      begin
        raise described_class, 'Auth failed'
      rescue KindeSdk::APIError
        rescued_as_api_error = true
      end
      expect(rescued_as_api_error).to be true
    end
  end

  describe KindeSdk::AuthorizationError do
    it 'inherits from APIError' do
      expect(described_class.superclass).to eq(KindeSdk::APIError)
    end

    it 'represents 403 forbidden errors' do
      error = described_class.new('Insufficient permissions')
      expect(error.message).to eq('Insufficient permissions')
    end

    it 'can be rescued as APIError' do
      rescued_as_api_error = false
      begin
        raise described_class, 'Forbidden'
      rescue KindeSdk::APIError
        rescued_as_api_error = true
      end
      expect(rescued_as_api_error).to be true
    end
  end

  describe KindeSdk::RateLimitError do
    it 'inherits from APIError' do
      expect(described_class.superclass).to eq(KindeSdk::APIError)
    end

    it 'represents 429 too many requests errors' do
      error = described_class.new('Too many requests')
      expect(error.message).to eq('Too many requests')
    end

    it 'can be rescued as APIError' do
      rescued_as_api_error = false
      begin
        raise described_class, 'Rate limited'
      rescue KindeSdk::APIError
        rescued_as_api_error = true
      end
      expect(rescued_as_api_error).to be true
    end
  end

  describe 'Error hierarchy' do
    it 'allows catching all SDK errors with KindeSdk::Error' do
      errors = [
        KindeSdk::Error,
        KindeSdk::APIError,
        KindeSdk::AuthenticationError,
        KindeSdk::AuthorizationError,
        KindeSdk::RateLimitError
      ]

      errors.each do |error_class|
        caught = false
        begin
          raise error_class, 'Test'
        rescue KindeSdk::Error
          caught = true
        end
        expect(caught).to be(true), "Expected #{error_class} to be catchable as KindeSdk::Error"
      end
    end

    it 'allows catching all API errors with APIError' do
      api_errors = [
        KindeSdk::APIError,
        KindeSdk::AuthenticationError,
        KindeSdk::AuthorizationError,
        KindeSdk::RateLimitError
      ]

      api_errors.each do |error_class|
        caught = false
        begin
          raise error_class, 'Test'
        rescue KindeSdk::APIError
          caught = true
        end
        expect(caught).to be(true), "Expected #{error_class} to be catchable as KindeSdk::APIError"
      end
    end
  end

  describe 'Error messages' do
    it 'preserves error messages through inheritance chain' do
      message = 'Specific error message with details'

      [
        KindeSdk::AuthenticationError,
        KindeSdk::AuthorizationError,
        KindeSdk::RateLimitError
      ].each do |error_class|
        error = error_class.new(message)
        expect(error.message).to eq(message)
      end
    end
  end
end



