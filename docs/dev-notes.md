
# Development notes

```ruby
require_relative "lib/zwiebel"
cookie_hash = Zwiebel.cookie_file_hash(file_path: "/run/tor/control.authcookie")

#
# New way
#
address = "p53lf57qovyuvwsc6xnrppyply3vtqm7l6pcobkmyqsiofyeznfu5uqd.onion"
Zwiebel.start(address, cookie: cookie_hash)

#
# Old way
#
tor = Zwiebel::Control.new(cookie: cookie_hash)
tor.authenticate

# Get Tor Socks IP:Port
tor.send_command("GETINFO", "net/listeners/socks")

tor.send_command("GETINFO", "circuit-status")
tor.send_command("GETINFO", "dormant")
tor.send_command("GETINFO", "uptime")
tor.send_command("GETINFO", "network-liveness")
tor.send_command("GETINFO", "version")
tor.send_command("GETINFO", "status/circuit-established")
tor.send_command("GETINFO", "status/enough-dir-info")
tor.send_command("GETINFO", "status/good-server-descriptor")
tor.send_command("GETINFO", "status/reachability-succeeded")
tor.send_command("GETINFO", "status/bootstrap-phase")
tor.send_command("GETINFO", "status/bootstrap-phase")
tor.send_command("SIGNAL", "CLEARDNSCACHE")
tor.send_command("SIGNAL", "NEWNYM")
tor.send_command("SIGNAL", "ACTIVE")

tor.send_command("GETINFO", "md/all")
results = []
reply = tor.read_reply
while reply != "250 OK"
  reply = tor.read_reply
  results << reply
end

ddg_address = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad"
raise "Invalid" unless Zwiebel.v3_address_valid?("#{ddg_address}.onion")

tor.send_command("GETINFO", "hs/client/desc/id/#{ddg_address}")

hs_reply = tor.read_reply
if hs_reply.start_with?("551")
  # Not in cache. Look up, then check again
  tor.send_command("HSFETCH", ddg_address)
  raise "HSFETCH issue" unless tor.read_reply == "250 OK"
  tor.send_command("GETINFO", "hs/client/desc/id/#{ddg_address}")
  hs_reply = tor.read_reply
end

hs_descriptor = {}
descriptor_current_field = nil
fields = %w(hs-descriptor descriptor-lifetime descriptor-signing-key-cert revision-counter superencrypted signature)

while hs_reply != "250 OK"
  hs_reply = tor.read_reply
  next if hs_reply == "." || hs_reply == "250 OK"

  # Save response in object, key/value format
  # {
  #   "hs-descriptor" => "3",
  #   "descriptor-lifetime" => "180",
  #   "descriptor_signing-key-cert" => "-----BEGIN ED25519 CERT-----cert-----END ED25519 CERT-----",
  #   # etc
  # }

  hs_reply_field = hs_reply.split(" ")[0]
  if fields.include?(hs_reply_field)
    descriptor_current_field = hs_reply_field

    if hs_descriptor[descriptor_current_field].nil? && !hs_reply.split(" ")[1..-1].nil?
      hs_descriptor[descriptor_current_field] = hs_reply.split(" ")[1..-1].join(" ")
    else
      hs_descriptor[descriptor_current_field] = ""
    end
  else
    hs_descriptor_value = hs_descriptor[descriptor_current_field]

    if hs_descriptor_value.nil?
      hs_descriptor[descriptor_current_field] = hs_reply
    else
      hs_descriptor[descriptor_current_field] = hs_descriptor_value + hs_reply
    end
  end

end

```


## Tor notes

If Tor cannot retrieve current consensus, move or remove any cached files in `/var/lib/tor`

+ cached-certs
+ cached-microdesc-consensus
+ cached-microdescs
+ lock
+ state

## Relays

tor-spec.txt
6.2 Opening streams and transferring data

Constructs a RELAY_BEGIN cell.

If cannot be created, RELAY_END is replied.
Otherwise, RELAY_CONNECTED cell is replied.

Data cells now in RELAY_DATA.

Streams are automatically added to circuits by Tor.

How to add a stream to Tor?
"When a client application creates a new stream (by opening a SOCKS connection or launching a resolve request)
we attach it to an appropriate open circuit if one exists, or wit if an appropriate circuit is in-progress.

Send a SOCKS connection to the Tor socks port
