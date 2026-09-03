$:.unshift File.expand_path('..', __FILE__)
$:.unshift File.expand_path('../../lib', __FILE__)
require 'simplecov'
SimpleCov.start do
  minimum_coverage(75.00)
end
require 'rspec'
require 'rack/test'
require 'webmock/rspec'
require 'vcr'
require 'omniauth'
require 'omniauth-line'

VCR.configure do |config|
  config.cassette_library_dir = File.expand_path('cassettes', __dir__)
  config.hook_into :webmock
  # :once records against the real LINE API when a cassette is missing and
  # replays it forever after; on CI a missing cassette is a hard failure
  # instead of a network call.
  config.default_cassette_options = { record: ENV['CI'] ? :none : :once }
  config.filter_sensitive_data('<CHANNEL_SECRET>') { 'secret' }
end

RSpec.configure do |config|
  config.include WebMock::API
  config.include Rack::Test::Methods
  config.extend  OmniAuth::Test::StrategyMacros, :type => :strategy
  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
end
