(ns testsip.core
  (:require [org.httpkit.client :as http]
            [clojure.data.json :as json]
            )
  (:import
    ["javax.sip"]
           ;["org.mobicents.ext.javax.sip"]
           ;(javax.sip.address SipURI)
           ;(javax.sip.message Request)
           )
  ;(:use [cljain.dum])
  (:gen-class))
(Thread/setDefaultUncaughtExceptionHandler
  (reify
    Thread$UncaughtExceptionHandler
    (uncaughtException [this thread throwable]
      (println "ERROR" throwable))))
;(org.mobicents.ext.javax.sip.dns.DefaultDNSServerLocator)

(defn authenticate []
  (let [url "https://oauth.ring.com/oauth/token"
        {:keys [status headers body error] :as resp} @(http/request {:url url
                                                                     :method :post
                                                                     :headers {"Content-type" "application/json"}
                                                                     :body  (json/write-str {"client_id" "ring_official_android"
                                                                                             "grant_type" "password"

                                                                                             "scope" "client"
                                                                                             })
                                                                     })]
    (json/read-str body)
    )
  )
(def token (get (authenticate) "access_token"))

(defn get-active-ding []
  (let [url "https://api.ring.com/clients_api/dings/active?api_version=11"
        {:keys [status headers body error] :as resp} @(http/request {:url url
                                                                     :method :get
                                                                     :headers {"Authorization" (str "Bearer " token)}
                                                                     })]
    (json/read-str body)
    )
  )

(defn start-vod []
  (let [url "https://api.ring.com/clients_api/doorbots/15144637/vod?api_version=11"
        {:keys [status headers body error] :as resp} @(http/request {:url url
                                                                     :method :post
                                                                     :headers {"Content-type" "application/json"
                                                                               "Authorization" (str "Bearer " token)}
                                                                     ;:body  {}
                                                                     })]
    status
    )
  )


;(start-vod)
;(get-active-ding)
(defn request-video []
  (start-vod)
  (get (first (get-active-ding)) "sip_to" )
  )

(defn got-response [this res-ev]
  (let [response (.getResponse res-ev)]
    (println "got response")
    (println response)
    )
  )
(def listener
  (reify javax.sip.SipListener
    (processRequest [this req-ev]
      (println "processRequest!!")
      (println req-ev)
      )
    (processResponse [this res-ev]
        (got-response this res-ev)
      )
    (processTimeout [this to-ev]
      (println "process timeout!!")
      (println to-ev)
      ))
  )
(def trusty
  (reify gov.nist.javax.sip.TlsSecurityPolicy
    (enforceTlsPolicy [this transaction]
      (println "enforcetls!!")
      )
    )
  )
;(.getName (class trusty))
;; 	test.time@sip5060.net
;(.createURI (.createAddressFactory (doto (javax.sip.SipFactory/getInstance)
;                                     (.setPathName "gov.nist")
;                                     )) "sip:904@mouselike.org:5060")


(defn reset-factory []
  (.resetFactory (javax.sip.SipFactory/getInstance))
  )

(defn create-sip-stack []
  (let [sipfactory (doto (javax.sip.SipFactory/getInstance)
                     (.setPathName "gov.nist")
                     )
        properties (doto (java.util.Properties.)

                     ;properties.setProperty("gov.nist.javax.sip.TLS_SECURITY_POLICY" this.getClass().getName());
                     ;(.setProperty "gov.nist.javax.sip.TLS_CLIENT_AUTH_TYPE" "DisabledAll")
                     (.setProperty "gov.nist.javax.sip.TLS_SECURITY_POLICY" "gov.nist.javax.sip.stack.DefaultTlsSecurityPolicy")
                     (.setProperty "javax.sip.STACK_NAME" "shootist")
                     (.setProperty "gov.nist.javax.sip.DEBUG_LOG" "shootistdebug.txt")
                     (.setProperty "gov.nist.javax.sip.SERVER_LOG" "shootistlog.txt")
                     ;// Drop the client connection after we are done with the transaction.
                     (.setProperty "gov.nist.javax.sip.CACHE_CLIENT_CONNECTIONS" "false")
                     ;// Set to 0 (or NONE) in your production code for max speed.
                     ;// You need 16 (or TRACE) for logging traces. 32 (or DEBUG) for debug + traces.
                     ;// Your code will limp at 32 but it is best for debugging.
                     (.setProperty "gov.nist.javax.sip.TRACE_LEVEL" "DEBUG")
                     )
        ]
    (.createSipStack sipfactory properties)
    )
  )
(def local-ip "192.168.1.4")
(def sip-stack (create-sip-stack))
(def udp-listening-point (.createListeningPoint sip-stack local-ip 5060 "udp"))
(def tcp-listening-point (.createListeningPoint sip-stack local-ip 5060 "tcp"))
(def tls-listening-point (.createListeningPoint sip-stack local-ip 5061 "tls"))

(def udp-sip-provider (doto (.createSipProvider sip-stack udp-listening-point)
                    (.addSipListener listener)
                    ))
(def tcp-sip-provider (doto (.createSipProvider sip-stack tcp-listening-point)
                        (.addSipListener listener)
                        ))
(def tls-sip-provider (doto (.createSipProvider sip-stack tls-listening-point)
                        (.addSipListener listener)
                        ))
;(doto (.createSipProvider sip-stack tcp-listening-point)
;  ;(.addSipListener listener)
;  )

;"sip:5njgu9k0ee5lt-2030clpuumjogq@35.174.122.69:15064;transport=tls"
;(defn delete-listening-point []
;  (.deleteListeningPoint sip-stack listening-point)
;  )
;(reset-factory)
;(delete-listening-point)
; (.createAddress
;   (.createAddressFactory (javax.sip.SipFactory/getInstance))
;   (.createSipURI (.createAddressFactory (javax.sip.SipFactory/getInstance)) "904" "mouselike.org")
;   )
;(.createURI (.createAddressFactory (javax.sip.SipFactory/getInstance)) "sip:904@mouselike.org:5060;transport=tls")
;echo@conference.sip2sip.info;transport=tls
(defn make-a-call [dest-uri transport sip-provider]
  (let [sipfactory (javax.sip.SipFactory/getInstance)
        ;sipstack (create-sip-stack)
        headerFactory (.createHeaderFactory sipfactory)
        addressFactory (.createAddressFactory sipfactory)
        messageFactory (.createMessageFactory sipfactory)
        fromNameAddress (doto (.createAddress addressFactory (.createSipURI addressFactory "bhdev" local-ip))
                          (.setDisplayName "bhdev")
                          )
        fromHeader (.createFromHeader headerFactory fromNameAddress "12346")
        ;toNameAddress (.createAddress addressFactory (.createSipURI addressFactory "904" "mouselike.org"))
        ;toNameAddress (.createAddress addressFactory "sip:904@mouselike.org:5060")
        ;toHeader (.createToHeader headerFactory toNameAddress nil)
        toHeader (.createToHeader headerFactory (.createAddress addressFactory dest-uri) nil)
        requestURI (.createURI addressFactory dest-uri)
        ;ipAddress (.getIPAddress udpListeningPoint)
        viaHeader (.createViaHeader headerFactory
                                    local-ip
                                    (.getPort (.getListeningPoint sip-provider transport))
                                    transport
                                    nil
                                    )
        contentTypeHeader (.createContentTypeHeader headerFactory "application" "sdp")
        callIdHeader (.getNewCallId sip-provider)
        cSeqHeader (.createCSeqHeader headerFactory (long 1) "INVITE") ;1L
        maxForwards (.createMaxForwardsHeader headerFactory 70)
        request (.createRequest messageFactory
                                requestURI "INVITE" callIdHeader
                                cSeqHeader fromHeader toHeader [viaHeader]
                                maxForwards
                                )
        ;contactUrl (doto (.createSipURI addressFactory "fromName" local-ip)
        ;             (.setPort (.getPort listening-point)) ;
        ;             (.setLrParam)
        ;             )
        contactURI (doto (.createSipURI addressFactory "bhdev" local-ip)
                     (.setPort (.getPort (.getListeningPoint sip-provider transport))) ;
                     )
        contactAddress (doto (.createAddress addressFactory contactURI)
                         (.setDisplayName "fromName")
                         )
        contactHeader (.createContactHeader headerFactory contactAddress)
        ;extensionHeader (.createHeader headerFactory "My-Header" "my header value")
        sdpData (str "v=0\n"
                     "o=4855 13760799956958020 13760799956958020 IN IP4 " local-ip "\n"
                     "s=Blink 3.1.0 (Linux)\n"
                     "t=0 0\n"
                     "m=audio 50004 RTP/AVP 113 9 0 8 101\n"
                     "c=IN IP4 " local-ip "\n"
                     ;"p=+46 8 52018010\n"
                     "a=rtcp:50005\n"
                     "a=rtpmap:113 opus/48000/2\n"
                     "a=rtpmap:9 G722/8000\n"
                     "a=rtpmap:0 PCMU/8000\n"
                     "a=rtpmap:8 PCMA/8000\n"
                     "a=rtpmap:101 telephone-event/8000\n"
                     "a=fmtp:101 0-16\n"
                     "a=sendrecv\n"
                     ;"a=rtpmap:0 PCMU/8000\r\n"
                     ;"a=rtpmap:4 G723/8000\r\n"
                     ;"a=rtpmap:18 G729A/8000\r\n"
                     ;"a=ptime:20\r\n"
                     )
        dummy1 (doto request
                 (.addHeader contactHeader)
                 ;(.addHeader extensionHeader)
                 ;(.setContent (byte-array (map byte sdpData)) contentTypeHeader) ; if not set, it sends only the invite and waits
                 )
        inviteTid (.getNewClientTransaction sip-provider request)
        dummy2 (.sendRequest inviteTid)
        ;dialog (.getDialog inviteTid)
        ]
    (println requestURI)
    )
  )
;(make-a-call "sip:904@mouselike.org:5060" "udp" udp-sip-provider) ;; doesnt support tcp or tls
;(make-a-call "sip:music@iptel.org:5060" "udp" udp-sip-provider)
;(make-a-call "sip:music@iptel.org:5060" "tcp" tcp-sip-provider)
;(make-a-call "sip:music@iptel.org:5060" "tls" tls-sip-provider)
;(make-a-call "sip:thetestcall@sip2sip.info" "tls" tls-sip-provider)
;sip:thetestcall@sip2sip.info;transport=tls
;(make-a-call "sip:echo@conference.sip2sip.info:5060" "udp"); supports tls
(make-a-call (request-video) "tls" tls-sip-provider)
;(request-video)
;CompilerException javax.sip.SipException: sun.security.validator.ValidatorException: PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target, compiling:(/home/bhdev/clojure/sip/testsip/src/testsip/core.clj:229:1)

(System/setProperty "javax.net.ssl.keyStore" "/home/bhdev/clojure/sip/testsip/selfsigned.jks" )
(System/setProperty "javax.net.ssl.trustStore" "/home/bhdev/clojure/sip/testsip/selfsigned.jks" )
(System/setProperty "javax.net.ssl.keyStorePassword" "passphrase" );
(System/setProperty  "javax.net.ssl.keyStoreType" "jks" );
(defn -main
  "I don't do a whole lot ... yet."
  [& args]
  (println "Hello, World!"))
