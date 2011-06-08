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

    def inject(url)
      found = false
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
      found
    end

  end
end
