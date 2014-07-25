Requirement:
- .NET Framework 4.5
- BouncyCastle C# Crypto library 1.7 (http://www.bouncycastle.org/csharp/)

Generate Token:
===============
TokenAuthGenerator.exe encrypt samplekey "expire=1598832000&ref_allow=*.TrustedDomain.com&ref_deny=Denied.com"
token=110ea31ac69c09a2db0bdd74238843631cdab498ff7e6e75cbd99cc4d05426ab679a57015d4e48438c97b921652daec62de3829f8ff437e27449cfdfc2f1e5d9fc47f14e91a51ea7



Decrypt Token:
===============
TokenAuthGenerator.exe decrypt samplekey 110ea31ac69c09a2db0bdd74238843631cdab498ff7e6e75cbd99cc4d05426ab679a57015d4e48438c97b921652daec62de3829f8ff437e27449cfdfc2f1e5d9fc47f14e91a51ea7
security parameters=expire=1598832000&ref_allow=*.TrustedDomain.com&ref_deny=Denied.com
