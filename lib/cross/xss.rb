module Cross
  module Attack
    class XSS

      def self.each

        evasions = [
          "<script>alert('cross canary');</script>",
          "/--><script>alert('cross canary');</script>",
          "/--></ScRiPt><ScRiPt>alert('cross canary');</ScRiPt>",
          "//;-->alert('cross canary');",
          "\"//;\nalert('cross canary');"
        ]
        evasions.each do |pattern|
          yield pattern if block_given?
        end
      
      end

    end
  end
end
