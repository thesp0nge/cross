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

    def authenticate?
      ! @options[:auth].nil?  and ! @options[:auth].empty? 
    end

    def crawl?
      @options[:crawl][:enabled]
    end

    def crawl(url)
      start if @agent.nil?

      links = []
      @agent.add_auth(url, @options[:auth][:username], @options[:auth][:password]) if authenticate?
      begin 
        page=@agent.get(url)
        page=@agent.get(url) if authenticate?
        page.links.each do |l|
          @agent.log.debug("Link found: #{l.href}") if debug?
          links << l.href
        end
      rescue Mechanize::UnauthorizedError
        return {:status=>'KO', :links=>[], :message=>'target website requires authentication'}
      rescue => e 
        return {:status=>'KO', :links=>links, :message=>e.to_s}
      end

      return {:status=>'OK', :links=>links, :message=>''}
    end

    def inject(url)
      start if @agent.nil?

      $logger.log "Authenticating to the app using #{@options[:auth][:username]}:#{@options[:auth][:password]}" if debug?

      @agent.add_auth(url, @options[:auth][:username], @options[:auth][:password]) if authenticate?

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
              $logger.log(page.body) if @options[:debug] if sc.children.text.include?("alert(#{Cross::Attack::XSS::CANARY})")
              return true if sc.children.text.include?("alert(#{Cross::Attack::XSS::CANARY})")
            end

            return false if options[:oneshot]

            attack_url.reset
          end
        end

      else
        begin
          page = @agent.get(url)
        rescue Mechanize::UnauthorizedError
          $logger.err 'Authentication failed. Giving up.'
          return false
        rescue Mechanize::ResponseCodeError
          $logger.err 'Server gave back 404. Giving up.'
          return false
        rescue Net::HTTP::Persistent::Error => e
          $logger.err e.message
          return false
        end

        $logger.log "#{page.forms.size} form(s) found" if debug?

        Cross::Attack::XSS.each do |pattern|

          $logger.log "using attack vector: #{pattern}" if debug?


          page.forms.each do |f|
            f.fields.each do |ff|
              if  options[:sample_post].empty?
                ff.value = pattern if options[:parameter_to_tamper].empty?
                ff.value = pattern if ! options[:parameter_to_tamper].empty? && ff.name==options[:parameter_to_tamper]
              else
                ff.value = find_sample_value_for(options[:sample_post], ff.name) unless ff.name==options[:parameter_to_tamper]
                ff.value = pattern if ff.name==options[:parameter_to_tamper]

              end
            end

            pp = @agent.submit(f)
            $logger.log "header: #{pp.header}" if debug? && ! pp.header.empty?
            $logger.log "body: #{pp.body}" if debug? && ! pp.body.empty?
            $logger.err "Page is empty" if pp.body.empty?
            scripts = pp.search("//script")
            scripts.each do |sc|
              return true if sc.children.text.include?("alert(#{Cross::Attack::XSS::CANARY})")
            end

            # This is for input html field javascript event evasion
            inputs = pp.search("//input")
            inputs.each do |input|
              return true if ! input['onmouseover'].nil? && input['onmouseover'].include?("alert(#{Cross::Attack::XSS::CANARY})") 
            end
          end 
          return false if options[:oneshot]
        end
      end
      found
    end


    private
    def find_sample_value_for(sample, name)
      v=sample.split('&')
      v.each do |post_param|
        post_param_v = post_param.split('=')
        return post_param_v[1] if post_param_v[0] == name
      end

      return ""
    end
  end
end
