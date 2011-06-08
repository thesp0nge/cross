require 'singleton'

module Cross
  class Engine
    include Singleton

    attr_reader :agent
    
    # Start the engine
    def start
      @agent = Mechanize.new {|a| a.log = Logger.new("cross.log")}
      @agent.user_agent_alias = 'Mac Safari'
    end 

  end
end
