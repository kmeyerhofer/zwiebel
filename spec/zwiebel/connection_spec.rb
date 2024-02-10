require_relative "../spec_helper"
Thread.report_on_exception = false

RSpec.describe "connection" do
  before(:each) do
    @server = TorTcpServer.new(port: 90500)
    @thread = Thread.new do
      @server.start
    end
    @tor_client = Zwiebel::Connection.new(port: 90500)
  end

  after(:each) do
    @server.socket.close
    @tor_client.close
  end

  it "connected" do
    expect(@tor_client.connected?).to eq true
  end

  it "send data" do
    @tor_client.send_line("data")
    expect(@tor_client.read_reply).to eq "data"
  end
end
