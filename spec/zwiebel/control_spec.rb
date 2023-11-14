require_relative "../spec_helper"
Thread.report_on_exception = false

RSpec.describe "Zwiebel::Control" do
  before(:each) do
    @server = TorTcpServer.new
    @thread = Thread.new do
      @server.start
    end
    @tor_client = Zwiebel::Control.new(port: 90511)
  end

  after(:each) do
    @server.socket.close
  end

  it "connected" do
    expect(@tor_client.connected?).to eq true
  end

  it "authenticated?, without first authenticating" do
    expect(@tor_client.authenticated?).to eq false
  end

  it "authenticated" do
    expect(@tor_client.authenticate).to eq true
    expect(@tor_client.authenticated?).to eq true
  end

  it "version" do
    expect(@tor_client.version).to eq "0.3.5"
  end

end
