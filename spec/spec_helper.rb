require "pry"
require "zwiebel"
require_relative "support/tor_tcp_server"

RSPEC_DIR = File.dirname __FILE__

RSpec.configure do |c|
  c.order = :random
  Kernel.srand(c.seed)
end
