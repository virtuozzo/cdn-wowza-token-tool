Require
-------------------------------------------
- Java7
- maven 2 or 3

Build
-------------------------------------------
- mvn clean install
- upon success of the build, you will find the jar(token-auth-generator.jar) file at the folder named 'target'

Usage
-------------------------------------------
java -jar (<primary_key> or <backup_key>) "<security_parameters>"

Supported Security Parameters
-------------------------------------------
- expire
-- number of seconds since Unix time(Epoch time)
-- UTC based
-- must not be earlier than current time
- ref_allow
-- referrer domain(e.g. google.com) or path(e.g. google.com/video/)
-- allow multiple referrers separated by comma (,) without space(s)
-- wildcard (*) allowed only at the beginning of a referrer, e.g. *.DOMAIN
-- do not append space at the start & end of a referrer
-- domain must fullfill RFC 3490
-- path must fullfill RFC 2396
-- should not include port (e.g. google.com:3000/video)
-- should not include protocol(e.g. http) portion
- ref_deny
-- same rules to ref_allow
-- if both ref_allow & ref_deny are specified, ref_allow will be taking precedence over ref_deny

Generate Token
-------------------------------------------
cmd:
  java -jar token-auth-generator.jar encrypt samplekey "expire=1356955399&ref_allow=*.TrustedDomain.com&ref_deny=Denied.com"
result:
  token=110ea31ac69c09a2cb7854126719f5d3c3267d24c723eea5cbd99cc4d05426ab679a57015d4e48438c97b921652daec62de3829f8ff437e27449cfdfc2f1e5d9fc47f14e91a51ea7
  
Note: Then append the result to the playback URL.

Decrypt Token
-------------------------------------------
cmd:
  java -jar token-auth-generator.jar decrypt samplekey 110ea31ac69c09a2cb7854126719f5d3c3267d24c723eea5cbd99cc4d05426ab679a57015d4e48438c97b921652daec62de3829f8ff437e27449cfdfc2f1e5d9fc47f14e91a51ea7
result:
  security parameters=expire=1356955399&ref_allow=*.TrustedDomain.com&ref_deny=Denied.com

