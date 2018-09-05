using System;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using CommandLine;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;


namespace JWTGenerator
{
    [Verb("file", HelpText = "Generate asymmetric JWT token from private key")]
    public class FileOptions : OptionsBase
    {

        [Option('p', "private", Required = true, HelpText = "Private Key Path")]
        public string PrivateKeyPath { get; set; }
    }

    [Verb("thumb", HelpText = "Generate asymmetric JWT token from thumbprint")]
    public class ThumbprintOptions : OptionsBase
    {

        [Option('t', "thumbprint", Required = true, HelpText = "Thumbprint")]
        public string Thumbprint { get; set; }
    }

    public class OptionsBase
    {

        [Option('i', "issuer", Required = true, HelpText = "JWT Token Issuer")]
        public string Issuer { get; set; }

        [Option('a', "audience", Required = true, HelpText = "JWT Token Audience")]
        public string Audience { get; set; }

        [Option('e', "expires", Required = false)]
        public string Expiration { get; set; }
    }

    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                string token = string.Empty;

                Parser.Default.ParseArguments<ThumbprintOptions, FileOptions>(args)
                    .WithParsed<ThumbprintOptions>(o =>
                    {

                        var key = GetPrivateKey(o.Thumbprint);
                        token = GetToken(o, key);
                    })
                    .WithParsed<FileOptions>(o =>
                    {
                        if (!System.IO.File.Exists(o.PrivateKeyPath))
                        {
                            throw new FileNotFoundException($"File {o.PrivateKeyPath} was not found.");
                        }
                        
                        var key = GetPrivateKey(o.PrivateKeyPath);

                        token = GetToken(o, key);
                    });

                if (!string.IsNullOrEmpty(token))
                {
                    Console.WriteLine($"{Environment.NewLine}{token}{Environment.NewLine}");
                }
            }
            catch (Exception ex)

            {
                Console.WriteLine(ex.Message);
            }

            Console.WriteLine("Press any key to exit.");
            Console.ReadLine();
        }
        
        private static string GetToken(OptionsBase o, SecurityKey key)
        {
            var creds = new SigningCredentials(key, SecurityAlgorithms.RsaSha256);
            var handler = new JwtSecurityTokenHandler();
            var jwtToken = new JwtSecurityToken(issuer: o.Issuer, audience: o.Audience, claims: null, signingCredentials: creds);

            return handler.WriteToken(jwtToken);

        }

        private static SecurityKey GetPrivateKey(string path)
        {
            using (var reader = File.OpenText(path)) // file containing RSA PKCS1 private key
            {
                var t = new PemReader(reader);
                var privateKey = (RsaPrivateCrtKeyParameters)t.ReadObject();

                var decryptEngine = new Pkcs1Encoding(new RsaEngine());
                decryptEngine.Init(false, privateKey);

                var paramerters = DotNetUtilities.ToRSAParameters(privateKey);

                return new RsaSecurityKey(paramerters);
            }

        }

        private static X509SecurityKey GetPrivateKeyFromThumbprint(string thumbprint)
        {
            thumbprint = Regex.Replace(thumbprint, @"[^\da-fA-F]", string.Empty).ToUpper();

            using (var certStore = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                certStore.Open(OpenFlags.MaxAllowed);

                var collection = certStore.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);

                if(collection.Count == 0) throw new Exception("Certificate not found!");

                return new X509SecurityKey(collection[0]);
            }
        }
    }
}
