(ns testsip.core
  (:require [org.httpkit.client :as http]
            [clojure.data.json :as json]
            [clojure.string :as str]
            )
  (:import
    [javax.sip SipListener SipFactory]
    (javax.sip SipListener SipFactory)
    )
  ;(:use [cljain.dum])
  (:gen-class))
(Thread/setDefaultUncaughtExceptionHandler
  (reify
    Thread$UncaughtExceptionHandler
    (uncaughtException [this thread throwable]
      (println "ERROR" throwable))))


(defn authenticate [user pass]
  (let [url "https://oauth.ring.com/oauth/token"
        {:keys [status headers body error] :as resp} @(http/request {:url url
                                                                     :method :post
                                                                     :headers {"Content-type" "application/json"}
                                                                     :body  (json/write-str {"client_id" "ring_official_android"
                                                                                             "grant_type" "password"
                                                                                             "username" user
                                                                                             "password" pass
                                                                                             "scope" "client"
                                                                                             })
                                                                     })]
    (if (= 200 status)
      (json/read-str body)
      )
    )
  )

(defn send-vod [token]
  (let [url "https://api.ring.com/clients_api/doorbots/15144637/vod?api_version=11"
        {:keys [status headers body error] :as resp} @(http/request {:url url
                                                                     :method :post
                                                                     :headers {"Content-type" "application/json"
                                                                               "Authorization" (str "Bearer " token)}
                                                                     ;:body  {}
                                                                     })

        ]
    (println resp)
    status
    )
  )
(defn get-active-ding [token]
  (let [url "https://api.ring.com/clients_api/dings/active?api_version=11"
        {:keys [status headers body error] :as resp} @(http/request {:url url
                                                                     :method :get
                                                                     :headers {"Authorization" (str "Bearer " token)}
                                                                     })

        ]
    (println resp)
    (if (= 200 status)
      (json/read-str body)
      )
    )
  )

(defn live-feed-sip [user pass]
  (let [token   (get (authenticate user pass) "access_token")
        video-started (send-vod token)
        ding-data (if (= 200 video-started)
                    (get-active-ding token)
                    )
        ]
    ding-data
    ;; FIXME: ding-data could be empty if we asked to fast, wait and retry?
    )
  )

(def stats (atom (json/read-str (slurp "stats.log"))))
(def from-stats (atom (json/read-str (slurp "from-stats.log"))))
;(def from-stats (atom nil))
(add-watch stats :watcher
           (fn [key atom old-state new-state]
             (spit "stats.log" (json/write-str new-state))
             )
           )
(add-watch from-stats :watcher2
           (fn [key atom old-state new-state]
             (spit "from-stats.log" (json/write-str new-state))
             )
           )


;(def dialog (atom nil))
(def currentTid (atom nil))
(def ackRequest (atom nil))
(def reInviteCount (atom 0))
(def to (atom nil))

(defn got-response [this res-ev]
  (let [response (.getResponse res-ev)
        tid (.getClientTransaction res-ev)
        cseq (.getHeader response "CSeq")
        code (.getStatusCode  response)
        content (str/split-lines (slurp (.getContent response)))
        ]
    (println "got response")
    (if (and (= (.getMethod cseq) "INVITE") (= code 200))
      (let [call (.getDialog tid)
            ack (.createAck call (.getSeqNumber cseq))
            ]
        (println ack)
        (.sendAck call ack)
        (println "sent ACK")
        )
      )
    (println response)
    )
  )

(defn got-request [this req-ev]
  (let [request (.getRequest req-ev)
        tid (.getServerTransaction req-ev)
        cseq (.getHeader request "CSeq")
        ]
    (println "got request")
    (if (= (.getMethod cseq) "BYE")
      (let [msg-factory (.createMessageFactory (SipFactory/getInstance))
            response (.createResponse msg-factory 200 request)
            ]
        (println response)
        (.sendResponse tid response)
        (println "sent OK to BYE")
        )
      )
    (println request)
    )
  )




(def listener
  (reify SipListener
    (processRequest [this req-ev]
      (got-request this req-ev)
      )
    (processResponse [this res-ev]
        (got-response this res-ev)
      )
    (processTimeout [this to-ev]
      (println "process timeout!!")
      (println to-ev)
      ))
  )

(defn reset-factory []
  (.resetFactory (SipFactory/getInstance))
  )

(defn create-sip-stack []
  (let [sipfactory (doto (SipFactory/getInstance)
                     (.setPathName "gov.nist")
                     )
        properties (doto (java.util.Properties.)

                     ;properties.setProperty("gov.nist.javax.sip.TLS_SECURITY_POLICY" this.getClass().getName());
                     ;(.setProperty "gov.nist.javax.sip.TLS_CLIENT_PROTOCOLS" "")
                     (.setProperty "gov.nist.javax.sip.TLS_CLIENT_AUTH_TYPE" "DisabledAll")
                     (.setProperty "javax.net.ssl.keyStorePassword" "passphrase")
                     (.setProperty "javax.net.ssl.keyStore" "/home/bhdev/clojure/sip/testsip/selfsigned.jks")
                     ;(.setProperty "gov.nist.javax.sip.TLS_SECURITY_POLICY" "gov.nist.javax.sip.stack.DefaultTlsSecurityPolicy")
                     (.setProperty "javax.sip.STACK_NAME" "shootist")
                     (.setProperty "gov.nist.javax.sip.DEBUG_LOG" "shootistdebug.txt")
                     (.setProperty "gov.nist.javax.sip.SERVER_LOG" "shootistlog.txt")
                     ;// Drop the client connection after we are done with the transaction.
                     (.setProperty "gov.nist.javax.sip.CACHE_CLIENT_CONNECTIONS" "false")
                     ;// Set to 0 (or NONE) in your production code for max speed.
                     ;// You need 16 (or TRACE) for logging traces. 32 (or DEBUG) for debug + traces.
                     ;// Your code will limp at 32 but it is best for debugging.
                     (.setProperty "gov.nist.javax.sip.TRACE_LEVEL" "DEBUG")
                     ;(.setProperty "javax.sip.USE_ROUTER_FOR_ALL_URIS" "true")
                     ;(.setProperty "gov.nist.javax.sip.ALWAYS_ADD_RPORT" "true")
                     )
        ]
    (.createSipStack sipfactory properties)
    )
  )
(def local-ip "192.168.1.4")
(def public-ip "167.57.150.9")
(def sip-stack (create-sip-stack))
(def udp-listening-point (.createListeningPoint sip-stack local-ip 50060 "udp"))
(def tcp-listening-point (.createListeningPoint sip-stack local-ip 50060 "tcp"))
(def tls-listening-point (.createListeningPoint sip-stack local-ip 50061 "tls"))
(def udp-sip-provider (doto (.createSipProvider sip-stack udp-listening-point)
                    (.addSipListener listener)
                    ))
(def tcp-sip-provider (doto (.createSipProvider sip-stack tcp-listening-point)
                        (.addSipListener listener)
                        ))
(def tls-sip-provider (doto (.createSipProvider sip-stack tls-listening-point)
                        (.addSipListener listener)
                        ))

(defn rand-tag
  [n]
   (let [chars-between #(map char (range (int %1) (inc (int %2))))
         chars (concat (chars-between \0 \9)
                       (chars-between \a \z)
                       (chars-between \A \Z)
                       )
         password (take n (repeatedly #(rand-nth chars)))]
     (reduce str password)))

(defn make-a-call [from-addr dest-uri transport sip-provider]
  (let [sipfactory (SipFactory/getInstance)
        headerFactory (.createHeaderFactory sipfactory)
        addressFactory (.createAddressFactory sipfactory)
        messageFactory (.createMessageFactory sipfactory)
        fromHeader (.createFromHeader headerFactory (.createAddress addressFactory from-addr) (rand-tag 13))
        toHeader (.createToHeader headerFactory (.createAddress addressFactory dest-uri) nil)
        requestURI (.createURI addressFactory dest-uri)
        viaHeader (doto (.createViaHeader headerFactory
                                          local-ip
                                          (.getPort (.getListeningPoint sip-provider transport))
                                          transport
                                          nil
                                          )
                    ;(.setRPort)
                    ;(.setBranch (branch))
                    )
        allowHeader (.createAllowHeader headerFactory "SUBSCRIBE, NOTIFY, INVITE, ACK, BYE, CANCEL, UPDATE, MESSAGE, REFER")
        supportedHeader (.createSupportedHeader headerFactory "replaces, norefersub, gruu")
        userAgentHeader (.createUserAgentHeader headerFactory ["ring/4.1.16 (iPhone; iOS 11.3; Scale/2.00)"])
        contentTypeHeader (.createContentTypeHeader headerFactory "application" "sdp")
        callIdHeader (.createCallIdHeader headerFactory
                                          ;(first (str/split (.getCallId (.getNewCallId sip-provider)) #"@"))
                                          (.getCallId (.getNewCallId sip-provider))
                                          )
        cSeqHeader (.createCSeqHeader headerFactory (rand-int 2500) "INVITE") ;1L
        maxForwards (.createMaxForwardsHeader headerFactory 70)
        request (.createRequest messageFactory
                                requestURI
                                "INVITE"
                                callIdHeader
                                cSeqHeader
                                fromHeader
                                toHeader
                                [viaHeader]
                                maxForwards
                                )
        contactHeader (.createContactHeader headerFactory
                                            (.createAddress addressFactory
                                                            (str "sip:" (rand-tag 8) "@" public-ip ":" (.getPort (.getListeningPoint sip-provider transport)) ";transport=" transport)
                                                            )
                                            )
        sdpData (str "v=0\n"
                     "o=- 3749391806 3749391806 IN IP4 " public-ip "\n"
                     "s=ring/4.1.16 (iPhone; iOS 11.3; Scale/2.00)\n"
                     "t=0 0\n"
                     "m=audio 50022 RTP/AVP 0 101\n"
                     "c=IN IP4 " public-ip "\n"
                     "a=rtcp:50023\n"
                     ;"a=rtpmap:113 opus/48000/2\n"
                     ;"a=fmtp:113 useinbandfec=1\n"
                     ;"a=rtpmap:9 G722/8000\n"
                     "a=rtpmap:0 PCMU/8000\n"
                     ;"a=rtpmap:8 PCMA/8000\n"
                     "a=rtpmap:101 telephone-event/8000\n"
                     "a=fmtp:101 0-16\n"
                     "a=sendrecv\n";; ???????????????
                     "m=video 50024 RTP/AVP 97 102\n"
                     "c=IN IP4 " public-ip "\n"
                     "a=rtcp:50025\n"
                     "a=rtpmap:97 H264/90000\n"
                     "a=fmtp:97 profile-level-id=42e01f;packetization-mode=1\n"
                     ;"a=rtpmap:102 VP8/90000\n"
                     "a=sendrecv\n"
                     )
        dummy1 (doto request
                 (.addHeader contactHeader)
                 (.addHeader allowHeader)
                 (.addHeader supportedHeader)
                 (.addHeader userAgentHeader)
                 (.setContent (byte-array (map byte sdpData)) contentTypeHeader) ; if not set, it sends only the invite and waits
                 )
        inviteTid (doto (.getNewClientTransaction sip-provider request)
                    (.sendRequest)
                    )
        ]
    ;(.sendRequest sip-provider request)
    (reset! ackRequest nil)
    (reset! to toHeader)
    (reset! currentTid inviteTid)
    ;(reset! dialog (.getDialog inviteTid))
    (reset! reInviteCount 0)
    )
  )


(defn start-rtp [user pass]
  (let [active (first (live-feed-sip user pass))
        video-url (get active "sip_to")
        from-sip (get active "sip_from") ;; not used? could be random?
        ]
    (swap! stats #(into #{} (conj % video-url)))
    (swap! from-stats #(into #{} (conj % from-sip)))
    (println video-url)
    (make-a-call from-sip video-url "tls" tls-sip-provider)
    )
  )

;(start-rtp "<<ring_username>>" "<<password>>")
;@stats
;@from-stats

(defn -main
  "I don't do a whole lot ... yet."
  [& args]
  (println "Hello, World!"))



;sdpData (str "v=0\r\n"
;             "o=- 3749391806 3749391806 IN IP4 " local-ip "\n"
;             "s=Blink 3.0.0 (Windows)\r\n"
;             "t=0 0\r\n"
;             "m=audio 50022 RTP/AVP 113 9 0 8 101\r\n"
;             "c=IN IP4 " local-ip "\n"
;             "a=rtcp:50023\r\n"
;             "a=rtpmap:113 opus/48000/2\r\n"
;             "a=fmtp:113 useinbandfec=1\r\n"
;             "a=rtpmap:9 G722/8000\r\n"
;             "a=rtpmap:0 PCMU/8000\r\n"
;             "a=rtpmap:8 PCMA/8000\r\n"
;             "a=rtpmap:101 telephone-event/8000\r\n"
;             "a=fmtp:101 0-16\r\n"
;             "a=sendrecv\r\n"
;             "m=video 50024 RTP/AVP 97 102\r\n"
;             "c=IN IP4 " local-ip "\n"
;             "a=rtcp:50025\r\n"
;             "a=rtpmap:97 H264/90000\r\n"
;             "a=fmtp:97 profile-level-id=42e01f;packetization-mode=1\r\n"
;             "a=rtpmap:102 VP8/90000\r\n"
;             "a=sendrecv\r\n"
;             )
;        sdpData (str
;"v=0\no=- 3749830081 3749830081 IN IP4 192.168.1.4\ns=Blink 3.0.0 (Windows)\nt=0 0\nm=audio 50016 RTP/AVP 113 9 0 8 101\nc=IN IP4 192.168.1.4\na=rtcp:50017\na=rtpmap:113 opus/48000/2\na=fmtp:113 useinbandfec=1\na=rtpmap:9 G722/8000\na=rtpmap:0 PCMU/8000\na=rtpmap:8 PCMA/8000\na=rtpmap:101 telephone-event/8000\na=fmtp:101 0-16\na=sendrecv\n"
;                  )

;(doto (.createViaHeader (.createHeaderFactory (SipFactory/getInstance))
;                            "192.168.1.4"
;                            9678
;                            "udp"
;                            nil
;                            )
;  (.setRPort))

; (doto (.createSipURI (.createAddressFactory (SipFactory/getInstance)) "bhdev" local-ip)
;             (.setPort 15064)
;             ;(.setLrParam) ;; mierda
;             )
; (.createAddress (.createAddressFactory (SipFactory/getInstance))  (doto (.createSipURI (.createAddressFactory (SipFactory/getInstance)) "bhdev" local-ip)
;                                                                                   (.setPort 15064)
;                                                                                   ;(.setLrParam) ;; mierda
;                                                                                   ))
; (.createContactHeader (.createHeaderFactory (SipFactory/getInstance))  (.createAddress (.createAddressFactory (SipFactory/getInstance))  (doto (.createSipURI (.createAddressFactory (SipFactory/getInstance)) "bhdev" local-ip)
;                                                                                                                                            (.setPort 15064)
;                                                                                                                                            ;(.setLrParam) ;; mierda
;                                                                                                                                            )))
;(.createContactHeader (.createHeaderFactory (SipFactory/getInstance))
;                      (.createAddress (.createAddressFactory (SipFactory/getInstance)) "sip:65298107@192.168.1.4:50327;transport=tls")
;                      )
;(branch)
;(count "Pja5140cff04794425a8f9dfd5bc978dc8")
;"z9hG4bK"
;;(.getNewCallId udp-sip-provider)
;(first (str/split (.getCallId (.getNewCallId udp-sip-provider)) #"@"))

;(def cont "v=0\no=Wantajobinstead? 1540527103 1540527104 IN IP4 18.206.167.111\ns=Wantajobinstead?\nc=IN IP4 18.206.167.111\nt=0 0\nm=audio 30850 RTP/AVP 0 101\na=rtpmap:0 PCMU/8000\na=rtpmap:101 telephone-event/8000\na=fmtp:101 0-16\na=ptime:20\na=rtcp:30851 IN IP4 18.206.167.111\nm=video 37748 RTP/AVP 97\na=rtpmap:97 H264/90000\na=fmtp:97 profile-level-id=42e01f;packetization-mode=1\na=rtcp:37749 IN IP4 18.206.167.111")
;(let [lines (str/split-lines cont)
;      rtcp (filter #(str/starts-with? % "a=rtcp:") lines)
;      video-data (str/split (second (str/split (second rtcp) #":")) #" ")
;      video-url (str "rtp://@" (last video-data) ":" (first video-data) "/")
;      ]
;  ;rtcp;first is audio, second is video?
;  video-url
;  )

;; a=rtcp:57531 IN IP4 18.206.166.106



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
;(make-a-call "sip:904@mouselike.org:5060" "udp" udp-sip-provider) ;; doesnt support tcp or tls
;(make-a-call "sip:music@iptel.org:5060" "udp" udp-sip-provider)
;(make-a-call "sip:music@iptel.org:5060" "tcp" tcp-sip-provider)
;(make-a-call "sip:music@iptel.org:5060" "tls" tls-sip-provider)
;(make-a-call "sip:thetestcall@sip2sip.info" "tls" tls-sip-provider)
;sip:thetestcall@sip2sip.info;transport=tls
;(make-a-call "sip:echo@conference.sip2sip.info:5060" "udp"); supports tls
;(let [uri (request-video)
;      server (first (str/split (second (str/split uri #"@")) #";"))
;      cmd
;      ])


;(.getClientAuth sip-stack)
;(gov.nist.javax.sip.stack.ClientAuthType/DisabledAll)
;(first (str/split (second (str/split "sip:5nkglfo0ee5lt-2030clpuumjogq@35.174.123.56:15064;transport=tls" #"@")) #";"))

;(request-video)
;CompilerException javax.sip.SipException: sun.security.validator.ValidatorException: PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target, compiling:(/home/bhdev/clojure/sip/testsip/src/testsip/core.clj:229:1)

;(System/setProperty "javax.net.ssl.keyStore" "/home/bhdev/clojure/sip/testsip/selfsigned.jks" )
;(System/setProperty "javax.net.ssl.trustStore" "/home/bhdev/clojure/sip/testsip/selfsigned.jks" )
;(System/setProperty "javax.net.ssl.keyStorePassword" "passphrase" );
;(System/setProperty  "javax.net.ssl.keyStoreType" "jks" );
;(System/setProperty  "javax.net.debug" "all" );
;(System/setProperty  "com.sun.net.ssl.checkRevocation" "false" );com.sun.net.ssl.checkRevocation=false
;javax.net.debug=all



