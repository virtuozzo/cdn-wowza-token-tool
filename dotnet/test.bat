@echo off
cls

echo TokenAuthGenerator.exe encrypt samplekey "expire=1356955399&ref_allow=*.TrustedDomain.com&ref_deny=Denied.com"

TokenAuthGenerator.exe encrypt samplekey "expire=1356955399&ref_allow=*.TrustedDomain.com&ref_deny=Denied.com"
pause

echo TokenAuthGenerator.exe decrypt samplekey 110ea31ac69c09a2cb7854126719f5d3c3267d24c723eea5cbd99cc4d05426ab679a57015d4e48438c97b921652daec62de3829f8ff437e27449cfdfc2f1e5d9fc47f14e91a51ea7


TokenAuthGenerator.exe decrypt samplekey 110ea31ac69c09a2cb7854126719f5d3c3267d24c723eea5cbd99cc4d05426ab679a57015d4e48438c97b921652daec62de3829f8ff437e27449cfdfc2f1e5d9fc47f14e91a51ea7
pause
