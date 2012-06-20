require 'singleton'

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
      found = false
      if options[:exploit_url]
        # You ask to exploit the url, so I won't check for form values

        page = @agent.get(url+"<script>alert('cross canary');</script>")
        scripts = page.search("//script")
        scripts.each do |sc|
          if sc.children.text == "alert('cross canary');"
            found = true
          end
        end

        if options[:debug]
          puts page.body
        end

        page = @agent.get(url+"/--><script>alert('cross canary');</script>")
        scripts = page.search("//script")
        scripts.each do |sc|
          if sc.children.text == "alert('cross canary');"
            found = true
          end
        end

        if options[:debug]
          puts page.body
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
