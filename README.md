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

```ruby
onion_address = "qubesosfasa4zl44o4tws22di6kepyzfeqv3tg4e3ztknltfxqrymdad.onion"
if Zwiebel.v3_address_valid?(onion_address)
  # do something great
end
```

## License

This gem is available as open source under the terms of [LGPL-3 or later](https://www.gnu.org/licenses/lgpl-3.0.html).
