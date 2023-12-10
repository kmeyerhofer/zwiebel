
```ruby
require_relative 'lib/zwiebel'
cookie_hash = Zwiebel.cookie_file_hash(file_path: "/run/tor/control.authcookie")
tor = Zwiebel::Control.new(cookie: cookie_hash)
tor.authenticate


tor.send_command("GETINFO", "md/all")
results = []
reply = tor.read_reply
while reply != "250 OK"
  reply = tor.read_reply
  results << reply
end

ddg_address = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad"
raise "Invalid" unless Zwiebel.v3_address_valid?("#{ddg_address}.onion")

hs_descriptor = []
tor.send_command("GETINFO", "hs/client/desc/id/#{ddg_address}")

hs_reply = tor.read_reply
if hs_reply.start_with?('551')
  # Not in cache. Look up, then check again
  tor.send_command("HSFETCH", ddg_address)
  raise "HSFETCH issue" unless tor.read_reply == "250 OK"
  tor.send_command("GETINFO", "hs/client/desc/id/#{ddg_address}")
  hs_reply = tor.read_reply
end

while hs_reply != "250 OK"
  hs_reply = tor.read_reply
  hs_descriptor << hs_reply
end

```
