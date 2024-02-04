# Copyright 2023-2024, Kurt Meyerhofer
# This file is part of zwiebel.

# zwiebel is free software: you can redistribute it and/or modify it under the terms of
# the GNU Lesser General Public License as published by the Free Software Foundation,
# either version 3 of the License, or (at your option) any later version.

# zwiebel is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
# more details.

# You should have received a copy of the GNU Lesser General Public License along with zwiebel.
# If not, see <https://www.gnu.org/licenses/>.

module Zwiebel
  class Control
    attr_accessor :cookie, :host, :port, :socket

    def initialize(host: "127.0.0.1", port: 9051, cookie: nil)
      @host = host
      @port = port
      @cookie = cookie
      connect
    end

    def connect
      close
      @socket = TCPSocket.new(host, port)
      @socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_KEEPALIVE, true)
    end

    def connected?
      !@socket.nil?
    end

    def close
      @socket.close unless @socket.nil?
      @authenticated = false
      @socket = nil
    end

    def quit
      send_line("QUIT")
      reply = read_reply
      close
      reply
    end

    def authenticate
      send_line(@cookie ? "AUTHENTICATE #{cookie}" : "AUTHENTICATE")
      reply = read_reply
      @authenticated = reply == "250 OK"
    end

    def authenticated?
      !!@authenticated
    end

    def version
      send_command("GETINFO", "version")
      reply = read_reply.split("=").last
      read_reply
      reply
    end

    def send_command(command, *args)
      authenticate unless authenticated?
      send_line([command, *args].join(" "))
      whole_reply
    end

    def send_line(line)
      @socket.write("#{line}\r\n")
      @socket.flush
    end

    def read_reply
      @socket.readline.chomp
    end

    def whole_reply
      results = []
      reply = read_reply
      while reply != "250 OK"
        break if reply.start_with?("551")
        results.push(reply)
        reply = read_reply
      end
      results.push(reply)
      results
    end

    def dormant?
      reply = send_command("GETINFO", "dormant")
      reply[0].split("=")[1] == "1"
    end

    def circuit_established?
      reply = send_command("GETINFO", "status/circuit-established")
      reply[0].split("=")[1] == "1"
    end

    def bootstrap_progress
      reply = send_command("GETINFO", "status/bootstrap-phase")
      if reply[1] == "250 OK"
        reply[0].scan(/(?<=PROGRESS=)\d{1,3}/)
      else
        "0"
      end
    end

    def circuits
      reply = send_command("GETINFO", "circuit-status")
      if reply[-1] == "250 OK"
        reply.reject do |r|
          r == "250+circuit-status=" || r == "." || r == "250 OK"
        end
      else
        reply
      end
    end
  end
end
