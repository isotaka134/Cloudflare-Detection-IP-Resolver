require 'msf/core'
require 'resolv'
require 'net/http'
require 'uri'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'Cloudflare Detection & IP Resolver',
      'Description' => 'Scans a list of domains, resolves their IP addresses, and detects whether Cloudflare protects them',
      'Author'      => ['HAMZA EL-HAMDAOUI'],
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        OptPath.new('DOMAIN_LIST', [true, 'Path to the domain list file (e.g., domains.txt)']),
        OptString.new('OUTPUT_FILE', [false, 'Path to save the output results (optional)'])
      ]
    )
  end

  def clean_domain(domain)
    domain.gsub(%r{^https?://}, '') # Remove http:// and https://
  end

  def resolve_ip(domain)
    begin
      return Resolv.getaddress(domain)
    rescue Resolv::ResolvError
      return nil
    end
  end

  def is_cloudflare?(domain)
    begin
      response = Net::HTTP.get_response(URI("http://#{domain}"))
      return response.key?('cf-ray')
    rescue
      return false
    end
  end

  def run
    domain_list_path = datastore['DOMAIN_LIST']
    output_file_path = datastore['OUTPUT_FILE']

    unless File.exist?(domain_list_path)
      print_error("File not found: #{domain_list_path}")
      return
    end

    results = []

    File.readlines(domain_list_path).each do |line|
      domain = clean_domain(line.strip)
      next if domain.empty?

      print_status("Scanning: #{domain}")

      ip = resolve_ip(domain)
      if ip
        cloudflare_status = is_cloudflare?(domain) ? "Yes" : "No"
        result = "#{domain}, IP: #{ip}, Cloudflare: #{cloudflare_status}"
        results << result

        print_good(result)
      else
        print_error("Could not resolve: #{domain}")
      end
    end

    if output_file_path && !results.empty?
      File.open(output_file_path, "w") { |file| file.puts(results) }
      print_good("Results saved to #{output_file_path}")
    end

    print_status("Scan completed.")
  end
end
