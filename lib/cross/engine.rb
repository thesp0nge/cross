require 'mechanize'
require 'logger'
require 'singleton'

require 'cross/xss'

module Cross
  # Engine is the cross class using Mechanize to inject canary and check for
  # output
  class Engine
    include Singleton

    attr_reader :agent
    attr_accessor :options

    def debug?
      @options[:debug]
    end

    # Starts the engine
    def start(options={:exploit_url=>false, :debug=>false, :auth=>{}})
      @agent = Mechanize.new {|a| a.log = Logger.new("cross.log")}
      @agent.user_agent_alias = 'Mac Safari'
      @agent.agent.http.verify_mode = OpenSSL::SSL::VERIFY_NONE
      @options = options
    end 

    def inject(url)
      start if @agent.nil?

      if debug?
        puts "Authenticating to the app using #{@options[:auth][:username]}:#{@options[:auth][:password]}"
      end

      if ! @options[:auth].nil?  and ! @options[:auth].empty? 
        @agent.add_auth(url, @options[:auth][:username], @options[:auth][:password])
      end

      found = false
      if @options[:exploit_url]
        # You ask to exploit the url, so I won't check for form values

        attack_url = Cross::Url.new(url)

        Cross::Attack::XSS.each do |pattern|
          attack_url.params.each do |par|

            page = @agent.get(attack_url.fuzz(par[:name],pattern))
            @agent.log.debug(page.body) if debug?

            scripts = page.search("//script")
            scripts.each do |sc|
              found = true if sc.children.text.include?("alert('cross canary');")
              @agent.log.debug(sc.children.text) if @options[:debug]
            end

            puts "GET #{attack_url.to_s}: #{found}"
          attack_url.reset
          end
        end

      else
        begin
          page = @agent.get(url)
        rescue Mechanize::UnauthorizedError
          puts 'Authentication failed. Giving up.'
          return false
        end

        if debug?
          puts "#{page.forms.size} form(s) found"
        end

        page.forms.each do |f|
          f.fields.each do |ff|
            ff.value = "<script>alert('cross canary');</script>"
          end
          pp = @agent.submit(f)
          scripts = pp.search("//script")
          scripts.each do |sc|
            if sc.children.text == "alert('cross canary');"
              found = true
            end
          end
        end 
      end
      found
    end

  end
end
