require 'mechanize'
require 'logger'
require 'singleton'
require 'URI'

require 'cross/xss'

module Cross
  # Engine is the cross class using Mechanize to inject canary and check for
  # output
  class Engine
    include Singleton

    attr_reader   :agent
    attr_accessor :options
    attr_reader   :results
    attr_reader   :target

    
    def create_log_filename(target)
      begin
        return "cross_#{URI.parse(target).hostname.gsub('.', '_')}_#{Time.now.strftime("%Y%m%d")}.log"
      rescue
        return "cross_#{Time.now.strftime("%Y%m%d")}.log"
      end
    end

    # Starts the engine
    def start(options = {:exploit_url=>false, :debug=>false, :oneshot=>false, :sample_post=>"", :parameter_to_tamper=>"", :auth=>{:username=>nil, :password=>nil}, :target=>""})
      @agent = Mechanize.new {|a| a.log = Logger.new(create_log_filename(options[:target]))}
      @agent.user_agent_alias = 'Mac Safari'
      @agent.agent.http.verify_mode = OpenSSL::SSL::VERIFY_NONE
      @options = options
      @target = options[:target]
      @results = {}
    end 

    
    # def crawl(url)
    #   start if @agent.nil?

    #   links = []
    #   @agent.add_auth(url, @options[:auth][:username], @options[:auth][:password]) if authenticate?
    #   begin 
    #     page=@agent.get(url)
    #     page=@agent.get(url) if authenticate?
    #     page.links.each do |l|
    #       @agent.log.debug("Link found: #{l.href}") if debug?
    #       links << l.href
    #     end
    #   rescue Mechanize::UnauthorizedError
    #     return {:status=>'KO', :links=>[], :message=>'target website requires authentication'}
    #   rescue => e 
    #     return {:status=>'KO', :links=>links, :message=>e.to_s}
    #   end

    #   return {:status=>'OK', :links=>links, :message=>''}
    # end

    def inject
      start if @agent.nil?

      $logger.log "Authenticating to the app using #{@options[:auth][:username]}:#{@options[:auth][:password]}" if debug? && authenticate?

      @agent.add_auth(@target, @options[:auth][:username], @options[:auth][:password]) if authenticate?

      if @options[:exploit_url]
        # You ask to exploit the url, so I won't check for form values

        theurl= Cross::Url.new(@target)

        attack_url(theurl, Cross::Attack::XSS.rand) if oneshot?

        if ! oneshot?
          Cross::Attack::XSS.each do |pattern|
            attack_url(theurl, pattern)
          end
        end

      else
        begin
          page = @agent.get(@target)
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

        
        if page.forms.size == 0
          $logger.log "no forms found, please try to exploit #{@target} with the -u flag"
          return false
        else
          $logger.log "#{page.forms.size} form(s) found" if debug?
        end
        attack_form(page, Cross::Attack::XSS.rand) if oneshot?

        if ! oneshot?
          Cross::Attack::XSS.each do |pattern|
            attack_form(page, pattern)
          end
        end
      end
      @results.empty?
    end


    private

    def oneshot?
      @options[:oneshot]
    end

    def debug?
      @options[:debug]
    end
    def authenticate?
      ! ( @options[:auth][:username].nil?  &&  @options[:auth][:password].nil? )
    end

    def attack_url(url = Cross::Url.new, pattern)
      $logger.log "using attack vector: #{pattern}" if debug?
      url.params.each do |par|

        page = @agent.get(url.fuzz(par[:name],pattern))
        @agent.log.debug(page.body) if debug?

        scripts = page.search("//script")
        scripts.each do |sc|
          if sc.children.text.include?("alert(#{Cross::Attack::XSS::CANARY})")
            $logger.log(page.body) if @debug
            @results << {:page=>page.url, :method=>:get, :evidence=>sc.children.text, :param=>par}

            return true 
          end
        end

        inputs = page.search("//input")
        inputs.each do |input|
          if ! input['onmouseover'].nil? && input['onmouseover'].include?("alert(#{Cross::Attack::XSS::CANARY})")
            $logger.log(page.body) if @debug
            @results << {:page=>page.url, :method=>:get, :evidence=>input['onmouseover'], :param=>par}
            return true  
          end
        end

        url.reset
      end

      false
    end

    def attack_form(page = Mechanize::Page.new, pattern)
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
          if sc.children.text.include?("alert(#{Cross::Attack::XSS::CANARY})")
            $logger.log(page.body) if @debug
            @results << {:page=>page.url, :method=>:post, :evidence=>sc.children.text}
            return true 
          end
        end

        # This is for input html field javascript event evasion
        inputs = pp.search("//input")
        inputs.each do |input|
          if ! input['onmouseover'].nil? && input['onmouseover'].include?("alert(#{Cross::Attack::XSS::CANARY})")
            $logger.log(page.body) if @debug
            @results << {:page=>page.url, :method=>:post, :evidence=> input['onmouseover']}
            return true  
          end
        end
      end 

      false
    end

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
