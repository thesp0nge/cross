module Codesake
  module Core
    class Url

      attr_reader :url
      attr_reader :base_url
      attr_reader :params
      attr_reader :original_params

      def initialize(url)
        @url = url
        @params = []
        @original_params = []
        @base_url = url.split('?')[0]
        if has_params?
          p_array = url.split('?')[1].split('&')
          p_array.each do |p|
            pp = p.split('=')
            param = {}
            param[:name] = pp[0]
            param[:value] = pp[1] unless pp[1].nil?

            @params << param
            @original_params  << param.dup
          end
          @original_params.freeze
        end
      end

      def to_s
        "#{@base_url}?#{params_to_url}"
      end

      def fuzz(name, value)
        set(name, value)
        "#{@base_url}?#{params_to_url}"
      end

      def get(name)
        value = nil
        @params.each do |p|
          value = p[:value] if p[:name] == name
        end
        value
      end

      def set(name, value)
        @params.each do |p|
          p[:value] = value if p[:name] == name
        end
      end

      def reset
        @params = []
        @original_params.each do |p|
          @params << p.dup
        end
      end

      def has_params?
        ! @url.split('?')[1].nil?
      end
      def params_to_url
        ret = ""
        @params.each do |p|
          ret += "#{p[:name]}=#{p[:value]}"
          if !(p == @params.last) 
            ret +="&"
          end
        end
        ret

      end
    end

  end
end
