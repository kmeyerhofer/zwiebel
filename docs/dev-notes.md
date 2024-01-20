
# Development notes

```ruby
require_relative 'lib/zwiebel'
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
if hs_reply.start_with?('551')
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
