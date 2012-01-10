module Cross
  class Host
    attr_reader :host, :port

    def initialize(uri)
      begin
        uri = URI.parse(ARGV[0])
        @host = uri.host
        @port = uri.port
      rescue 
        @host = nil
        @port = nil
        ap 'Malformed host: ' + ARGV[0]
      end
    end
  end
end
