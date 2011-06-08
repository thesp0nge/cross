module Cross
  class Host
    attr_reader :host, :port
    def initialize(uri)
      uri = URI.parse(ARGV[0])
      @host = uri.host
      @port = uri.port
    end
  end
end
