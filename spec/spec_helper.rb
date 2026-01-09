# frozen_string_literal: true

# Load paths for the SDK
$LOAD_PATH.unshift File.expand_path('../lib', __dir__)
$LOAD_PATH.unshift File.expand_path('../kinde_api/lib', __dir__)

# Core dependencies
require 'securerandom'
require 'openssl'
require 'jwt'
require 'webmock/rspec'

# Load the SDK
require 'kinde_sdk'

# Configure Faraday for testing
require 'faraday'
Faraday.default_adapter = :test

# Disable all external network connections
WebMock.disable_net_connect!(allow_localhost: false)

# Load support files
Dir[File.join(__dir__, 'support', '**', '*.rb')].sort.each { |f| require f }

RSpec.configure do |config|
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = 'spec/examples.txt'

  # Disable monkey patching for cleaner specs
  config.disable_monkey_patching!

  # Run specs in random order to surface order dependencies
  config.order = :random
  Kernel.srand config.seed

  # Expectation configuration
  config.expect_with :rspec do |expectations|
    expectations.include_chain_clauses_in_custom_matcher_descriptions = true
    expectations.syntax = :expect
  end

  # Mock configuration
  config.mock_with :rspec do |mocks|
    mocks.verify_partial_doubles = true
  end

  # Shared context configuration
  config.shared_context_metadata_behavior = :apply_to_host_groups

  # Filter for focusing on specific tests
  config.filter_run_when_matching :focus

  # Reset WebMock between tests
  config.before(:each) do
    WebMock.reset!
  end

  # Clear any cached JWKS between tests
  config.after(:each) do
    KindeSdk.instance_variable_set(:@cached_jwks, nil) if KindeSdk.instance_variable_defined?(:@cached_jwks)
  end
end

# Provide a minimal Rails application for testing Rails-specific functionality
require 'rails'
require 'active_support/all'

unless Rails.application
  class TestRailsApplication < Rails::Application
    config.eager_load = false
    config.active_support.deprecation = :stderr
    config.secret_key_base = SecureRandom.hex(64)
  end

  Rails.application.initialize!
end

# Ensure Rails.logger is available
Rails.logger ||= Logger.new('/dev/null')
