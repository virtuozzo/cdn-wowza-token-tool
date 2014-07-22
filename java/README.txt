Require
------------------------
- Java7
- maven 2 or 3

Build
------------------------
- mvn clean install
- you will find the jar(token-auth-generator.jar) file at the folder named 'target'

Generate Token
------------------------
cmd:
  java -jar token-auth-generator.jar encrypt samplekey "expire=1356955399&ref_allow=*.TrustedDomain.com&ref_deny=Denied.com"
result:
  token=110ea31ac69c09a2cb7854126719f5d3c3267d24c723eea5cbd99cc4d05426ab679a57015d4e48438c97b921652daec62de3829f8ff437e27449cfdfc2f1e5d9fc47f14e91a51ea7

Decrypt Token
------------------------
cmd:
  java -jar token-auth-generator.jar decrypt samplekey 110ea31ac69c09a2cb7854126719f5d3c3267d24c723eea5cbd99cc4d05426ab679a57015d4e48438c97b921652daec62de3829f8ff437e27449cfdfc2f1e5d9fc47f14e91a51ea7
result:
  security parameters=expire=1356955399&ref_allow=*.TrustedDomain.com&ref_deny=Denied.com
