# frozen_string_literal: true

require 'spec_helper'

RSpec.describe KindeSdk::Logging do
  # Create a test class that includes the Logging module
  let(:test_class) do
    Class.new do
      include KindeSdk::Logging
    end
  end

  let(:instance) { test_class.new }

  describe 'module inclusion' do
    it 'provides log_error method' do
      expect(instance).to respond_to(:log_error)
    end

    it 'provides log_warning method' do
      expect(instance).to respond_to(:log_warning)
    end

    it 'provides log_info method' do
      expect(instance).to respond_to(:log_info)
    end

    it 'provides log_debug method' do
      expect(instance).to respond_to(:log_debug)
    end
  end

  describe '.write_log' do
    context 'with Rails logger available' do
      let(:mock_logger) { instance_double(Logger) }

      before do
        allow(KindeSdk::Logging).to receive(:resolve_logger).and_return(mock_logger)
      end

      it 'formats messages with [KindeSdk] prefix' do
        expect(mock_logger).to receive(:error).with('[KindeSdk] Test error message')
        KindeSdk::Logging.write_log(:error, 'Test error message')
      end

      it 'calls error level correctly' do
        expect(mock_logger).to receive(:error).with(/Test error/)
        KindeSdk::Logging.write_log(:error, 'Test error')
      end

      it 'calls warn level correctly' do
        expect(mock_logger).to receive(:warn).with(/Test warning/)
        KindeSdk::Logging.write_log(:warn, 'Test warning')
      end

      it 'calls info level correctly' do
        expect(mock_logger).to receive(:info).with(/Test info/)
        KindeSdk::Logging.write_log(:info, 'Test info')
      end

      it 'calls debug level correctly' do
        expect(mock_logger).to receive(:debug).with(/Test debug/)
        KindeSdk::Logging.write_log(:debug, 'Test debug')
      end
    end

    context 'without Rails logger (fallback behavior)' do
      before do
        allow(KindeSdk::Logging).to receive(:resolve_logger).and_return(nil)
      end

      it 'writes errors to stderr' do
        expect($stderr).to receive(:puts).with('[KindeSdk] Error message')
        KindeSdk::Logging.write_log(:error, 'Error message')
      end

      it 'writes warnings to stderr' do
        expect($stderr).to receive(:puts).with('[KindeSdk] Warning message')
        KindeSdk::Logging.write_log(:warn, 'Warning message')
      end

      context 'with KINDE_DEBUG enabled' do
        before do
          allow(ENV).to receive(:[]).with('KINDE_DEBUG').and_return('true')
        end

        it 'writes info to stdout' do
          expect($stdout).to receive(:puts).with('[KindeSdk] Info message')
          KindeSdk::Logging.write_log(:info, 'Info message')
        end

        it 'writes debug to stdout' do
          expect($stdout).to receive(:puts).with('[KindeSdk] Debug message')
          KindeSdk::Logging.write_log(:debug, 'Debug message')
        end
      end

      context 'with KINDE_DEBUG disabled' do
        before do
          allow(ENV).to receive(:[]).with('KINDE_DEBUG').and_return(nil)
        end

        it 'does not write info to stdout' do
          expect($stdout).not_to receive(:puts)
          KindeSdk::Logging.write_log(:info, 'Info message')
        end

        it 'does not write debug to stdout' do
          expect($stdout).not_to receive(:puts)
          KindeSdk::Logging.write_log(:debug, 'Debug message')
        end
      end
    end
  end

  describe '.resolve_logger' do
    context 'when Rails is defined with logger' do
      it 'returns Rails.logger' do
        # Rails is already defined in our test environment
        expect(KindeSdk::Logging.resolve_logger).to eq(Rails.logger)
      end
    end
  end

  describe 'instance method delegation' do
    let(:mock_logger) { instance_double(Logger) }

    before do
      allow(KindeSdk::Logging).to receive(:resolve_logger).and_return(mock_logger)
    end

    it 'log_error delegates to write_log with :error' do
      expect(mock_logger).to receive(:error).with('[KindeSdk] Instance error')
      instance.log_error('Instance error')
    end

    it 'log_warning delegates to write_log with :warn' do
      expect(mock_logger).to receive(:warn).with('[KindeSdk] Instance warning')
      instance.log_warning('Instance warning')
    end

    it 'log_info delegates to write_log with :info' do
      expect(mock_logger).to receive(:info).with('[KindeSdk] Instance info')
      instance.log_info('Instance info')
    end

    it 'log_debug delegates to write_log with :debug' do
      expect(mock_logger).to receive(:debug).with('[KindeSdk] Instance debug')
      instance.log_debug('Instance debug')
    end
  end

  describe 'usage in SDK modules' do
    include_context 'authenticated client'

    it 'Client includes Logging module' do
      expect(client).to respond_to(:log_error)
    end
  end
end



