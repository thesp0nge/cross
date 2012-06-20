module Cross
  class Host
    attr_reader :host, :port

    def initialize(uri)
      begin
        my_uri = URI.parse(uri)
        @host = uri.host
        @port = uri.port
      rescue 
        @host = nil
        @port = nil
      end
    end
  end
end
