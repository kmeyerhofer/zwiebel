require 'socket'

class TorTcpServer
  attr_reader :client, :socket

  def initialize(port: 90511)
    @socket = TCPServer.new(port)
    @socket.listen(5)
  end

  def start
    @client, client_sockaddr = @socket.accept

    loop do
      data = @client.recvfrom(1024)[0]&.chomp
      handle_data(data) if !data.nil?
    end
  end

  def handle_data(data)
    if @client
      if data.match?(/authenticate/i)
        @client.puts("250 OK\n")
      elsif data.match?(/version/i)
        @client.puts("250-version=0.3.5\n")
      else
        puts @client.puts("#{data}\n")
      end
    end
  end
end
