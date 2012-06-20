module Cross
  class Host
    attr_reader :host, :port

    def initialize(uri)
      begin
        my_uri = URI.parse(uri)
        @host = my_uri.host
        @port = my_uri.port
      rescue 
        @host = nil
        @port = nil
      end
    end
  end
end
