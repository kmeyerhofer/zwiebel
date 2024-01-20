# zwiebel

zwiebel is a Tor network hidden service connector for version 3 `.onion` addresses and is in active development.

## Install

```shell
gem install zwiebel
```

Add to your application's Gemfile
```ruby
gem "zwiebel"
```

## Usage

### Tor control API

```ruby
# cookie auth
cookie_hash = Zwiebel.cookie_file_hash(file_path: "/run/tor/control.authcookie")
tor = Zwiebel::Control.new(
  host: "127.0.0.1", # default
  port: 9051, # default
  cookie: cookie_hash
)
# use control protocol
tor.authenticate
tor.version
tor.send_command("GETINFO", "md/all")
tor.read_reply # read one line at a time
tor.quit
```

### Tor utility

```ruby
# V3 address checksum verification
onion_address = "qubesosfasa4zl44o4tws22di6kepyzfeqv3tg4e3ztknltfxqrymdad.onion"
if Zwiebel.v3_address_valid?(onion_address)
  # do something great
end

# read Tor auth cookie
cookie_hash = Zwiebel.cookie_file_hash(file_path: "/run/tor/control.authcookie")
```

## Development

### Releases

- Update `lib/version.rb`.
- Add `CHANGELOG` entry.
- `gem build zwiebel.gemspec`
- `gem push zwiebel-version.gem`
- Add version tag, on master branch after merging above changes - `git tag -a v0.0.3 -m "Version 0.0.3"`

## License

This gem is available as open source under the terms of [LGPL-3 or later](https://www.gnu.org/licenses/lgpl-3.0.html).
