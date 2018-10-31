(defproject testsip "0.1.0-SNAPSHOT"
  :description "FIXME: write description"
  :url "http://example.com/FIXME"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.8.0"]
                 [javax.sip/jain-sip-ri "1.3.0-91"]
                 [javax.sip/jain-sip-api "1.2.1.4"]
                 [log4j/log4j "1.2.17"]
                 [http-kit "2.3.0"]
                 [org.clojure/data.json "0.2.6"]
                 ;[org.restcomm.media/rtp "7.0.16"]
                 ;[org.mobicents.media.io/rtp "6.0.23"]
                 ;[org.mobicents.javax.sip/jain-sip-ext "1.3.33"] ;DNSLookup fixes
                 ]
  ;:resource-paths ["resources/lib"]
  :main ^:skip-aot testsip.core
  :target-path "target/%s"
  :profiles {:uberjar {:aot :all}})
