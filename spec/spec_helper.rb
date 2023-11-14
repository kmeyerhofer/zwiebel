require "zwiebel"
require_relative "support/tor_tcp_server"

RSpec.configure do |c|
  c.order = :random
  Kernel.srand(c.seed)
end
