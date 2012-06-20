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

    # Starts the engine
    def start
      @agent = Mechanize.new {|a| a.log = Logger.new("cross.log")}
      @agent.user_agent_alias = 'Mac Safari'
    end 

    def inject(url, options={:exploit_url=>false, :debug=>false})
      if @agent.nil?
        start
      end

      found = false
      if options[:exploit_url]
        # You ask to exploit the url, so I won't check for form values

        Cross::Attack::XSS.each do |pattern|
          page = agent.get(url+pattern)

          scripts = page.search("//script")
          scripts.each do |sc|
            if sc.children.text.include?("alert('cross canary');")
              found = true
            end
            if options[:debug]
              @agent.log.debug(sc.children.text)
            end
          end

          puts "GET #{url+pattern}: #{found}"
        end

      else
        page = @agent.get(url)
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
