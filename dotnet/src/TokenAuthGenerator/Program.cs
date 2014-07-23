using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;

namespace com.onapp.cdn
{
    class Program
    {
        private static readonly List<string> SUPPORTED_PARAM = new List<string>() { "expire", "ref_allow", "ref_deny" };
        
        private static Encoding encoding = Encoding.UTF8;
        private static IBlockCipher cipherEngine = new BlowfishEngine();
        private static IBlockCipherPadding padding = new Pkcs7Padding();

        private static string Cipher(bool encrypt, byte[] key, byte[] data)
        {
            PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(cipherEngine, padding);
            cipher.Init(encrypt, new KeyParameter(key));

            int size = cipher.GetOutputSize(data.Length);
            byte[] result = new byte[size];
            int position = cipher.ProcessBytes(data, 0, data.Length, result, 0);
            cipher.DoFinal(result, position);

            return encrypt ? BitConverter.ToString(result).Replace("-", String.Empty).ToLower() : encoding.GetString(result);
        }

        private static string Encrypt(string key, string parameters)
        {
            ValidateSecurityParameters(parameters);
            return Cipher(true, encoding.GetBytes(key), encoding.GetBytes(parameters));
        }

        private static string Decrypt(string key, string parameters)
        {
            return Cipher(false, encoding.GetBytes(key), StringToByteArray(parameters));
        }

        private static byte[] StringToByteArray(string hexString)
        {
            int charCount = hexString.Length;
            byte[] buffer = new byte[charCount / 2];

            for (int index = 0; index < charCount; index += 2)
            {
                buffer[index / 2] = Convert.ToByte(hexString.Substring(index, 2), 16);
            }

            return buffer;
        }

        private static void ValidateSecurityParameters(string parameters)
        {
            if (String.IsNullOrEmpty(parameters))
                throw new ArgumentException("Parameters must not be empty");

            string[] tokens = parameters.Split(new char[] { '&' });
            List<string> param_keys = new List<string>();

            foreach (string token in tokens)
            {
                string[] strArray = token.Split(new char[] { '=' });
                if (strArray.Length != 2 || String.IsNullOrEmpty(strArray[0]) || String.IsNullOrEmpty(strArray[1]))
                    throw new ArgumentException("Malformed key/value pair");

                string paramKey = strArray[0];
                string paramValue = strArray[1];

                if (!param_keys.Contains(paramKey))
                {
                    param_keys.Add(paramKey);
                }
                else
                {
                    throw new ArgumentException(String.Format("Duplicate key '{0}' is not allowed", paramKey));
                }

                if(!SUPPORTED_PARAM.Contains(paramKey))
                    throw new ArgumentException(String.Format("Unsupported parameter  '{0}'", paramKey));
            }
        }

        static void Main(string[] args)
        {
            if (args.Length != 3)
                throw new ArgumentException("Expected 3 arguments. Refer to README for usage");

            if (args[0] != "encrypt" && args[0] != "decrypt")
                throw new ArgumentException("Invalid action. Refer to README for usage");

            if (args[0] == "encrypt")
            {
                string key = args[1];
                string parameters = args[2];
                string encryptedStr = Encrypt(key, parameters);
                Console.WriteLine("token=" + encryptedStr);
            }
            else if (args[0] == "decrypt")
            {
                string key = args[1];
                string encryptedStr = args[2];
                Console.WriteLine("security parameters=" + Decrypt(key, encryptedStr));
            }
        }
    }
}
