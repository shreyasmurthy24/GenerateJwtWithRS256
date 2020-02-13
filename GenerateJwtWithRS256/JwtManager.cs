using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Threading.Tasks;

namespace HussmannSubscription
{
    public static class JwtManager
    {
        public static string PrivateKey { get; set; }

        private static dynamic strSecret = @"Enter the private secret (ideally should be read from Az Key Vault.)";

        public static Task<string> GenerateJwt()
        {
            //log.LogInformation("C# HTTP trigger function processed a request.");
            Int32 unixTimestamp = (Int32)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;
            Guid uuid = Guid.NewGuid();
            string guid = unixTimestamp.ToString() + uuid;

            dynamic payload1 = "{\"v\" :" + "\"2.0\", \"t\" :" + "\"" + unixTimestamp.ToString() + "\", \"n\" :" + "\"" + guid  + "\"}";

            //------------Or------------

            //This is just an example for a body/payload
            dynamic payload11 = new JwtPayload
            {
                { "version", "2.0" },
                { "unixtime",  unixTimestamp.ToString() },
                { "guid", unixTimestamp.ToString() + uuid }
            };
                        
            dynamic token = Sign(payload1);

            return token;
        }

        public static string Sign(dynamic payload)
        {
            List<string> segments = new List<string>();
            //JwtHeader header = Header;

            string header = @"{ ""alg"":""RS256"", ""typ"":""JWT"" }";

            DateTime issued = DateTime.Now;
            DateTime expire = DateTime.Now.AddHours(10);

            byte[] headerBytes = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(header, Formatting.None));
            byte[] payloadBytes = Encoding.UTF8.GetBytes(payload);

            segments.Add(UrlEncode(headerBytes));
            segments.Add(UrlEncode(payloadBytes));

            string stringToSign = string.Join(".", segments.ToArray());

            byte[] bytesToSign = Encoding.UTF8.GetBytes(stringToSign);

            byte[] keyBytes = Convert.FromBase64String(strSecret);

            var privKeyObj = Asn1Object.FromByteArray(keyBytes);


            var privStruct = RsaPrivateKeyStructure.GetInstance((Asn1Sequence)privKeyObj);

            ISigner sig = SignerUtilities.GetSigner(SignerName);

            sig.Init(true, new RsaKeyParameters(true, privStruct.Modulus, privStruct.PrivateExponent));

            sig.BlockUpdate(bytesToSign, 0, bytesToSign.Length);
            byte[] signature = sig.GenerateSignature();

            segments.Add(UrlEncode(signature));
            return string.Join(".", segments.ToArray());
        }

        public static string UrlEncode(byte[] input)
        {
            var output = Convert.ToBase64String(input);
            output = output.Split('=')[0];
            output = output.Replace('+', '-');
            output = output.Replace('/', '_');
            return output;
        }

        private static JwtHeader Header
        {
            get
            {
                JwtHeader header = new JwtHeader();
                header.Add("typ", "JWT");
                return header;
            }
        }

        private static string SignerName
        {
            get
            {
                return "SHA" + "256" + "withRSA";
            }
        }

        private static string AlgorithmName
        {
            get
            {
                return "SHA" + "256";
            }
        }

        public enum Algorithm
        {
            HMAC = 1,
            RSA = 2,
            ECDSA = 3,
            RSASSA = 4
        }
    }
}