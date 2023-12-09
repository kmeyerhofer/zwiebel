
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

```
