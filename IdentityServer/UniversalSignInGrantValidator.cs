using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using IdentityServer.Services;
using IdentityServer3.Core;
using IdentityServer3.Core.Models;
using IdentityServer3.Core.Services;
using IdentityServer3.Core.Validation;
using Newtonsoft.Json;

namespace IdentityServer
{
    public class UniversalSignInGrantValidator : ICustomGrantValidator
    {


        public async Task<CustomGrantValidationResult> ValidateAsync(ValidatedTokenRequest request)
        {
            await Task.Delay(1);

            var token = request.Raw.Get("Token");
            var ip = request.Raw.Get("EndUserIp");
            var ua = request.Raw.Get("EndUserUserAgent");

            if (string.IsNullOrEmpty(token))
                return new CustomGrantValidationResult($"Missing '{nameof(token)}' parameter.");

            if (string.IsNullOrEmpty(ip))
                return new CustomGrantValidationResult($"Missing '{nameof(ip)}' parameter.");

            if (string.IsNullOrEmpty(ua))
                return new CustomGrantValidationResult($"Missing '{nameof(ua)}' parameter.");

            var usit = UniversalSignInToken.FromEncrypted(request.Client, token);

            // TODO shitty approach
            var claims = new List<Claim>
            {
                new Claim("__delegating_sid", usit.Sid)
            };

            return new CustomGrantValidationResult(usit.Sub, GrantType, claims);

        }

        public string GrantType => "universal_signin";
    }

    public class CustomTokenResponseGenerator : ICustomTokenResponseGenerator
    {
        private IUniversalSignInCodeStore universalSignInCodeStore;

        private class CustomTokenResponseGeneratorConfig
        {
            public string Uri { get; }

            public CustomTokenResponseGeneratorConfig(string uri)
            {
                Uri = uri;
            }
        }

        private static readonly IDictionary<string, CustomTokenResponseGeneratorConfig> Database = new Dictionary<string, CustomTokenResponseGeneratorConfig>
        {
            // TODO użyć adresów z np. ".gif"?
            ["websitepracuj"] = new CustomTokenResponseGeneratorConfig("http://website-pracuj.sso/Auth/UniversalOidcSignIn"),
            ["websitecv"] = new CustomTokenResponseGeneratorConfig("http://website-cv.sso/Auth/UniversalOidcSignIn"),
            ["websitepracodawcy"] = new CustomTokenResponseGeneratorConfig("http://website-pracodawcy.sso/Auth/UniversalOidcSignIn")
        };

        private static readonly ICollection<string> AllowedClients = new List<string> { "websitepracuj", "websitecv", "websitepracodawcy" };

        private readonly IClientStore clientStore;
        private readonly TokenValidator tokenValidator;

        public CustomTokenResponseGenerator(IClientStore clientStore, TokenValidator tokenValidator)
        {
            this.clientStore = clientStore;
            this.tokenValidator = tokenValidator;
        }

        public async Task<TokenResponse> GenerateAsync(ValidatedTokenRequest request, TokenResponse response)
        {
            var delegatingSidClaim = request?.Subject?.Claims?.FirstOrDefault(c => c.Type == "__delegating_sid");

            if (delegatingSidClaim != null)
            {
                response.Custom.Add(delegatingSidClaim.Type, delegatingSidClaim.Value);
            }

            /*
             * TODO Przepisać pod IdSrv4 w przyszłości
             * 
             * IdSrv4 pozwala na dodanie własnych właściwości w konf. klienta - tam pojawiłoby się "universal_signin_uri" oraz "universal_signin_XXX"
             * Tutaj wybrałoby się wsyzstkich klientów z tą pierwszą właściwością zamiast robić listę na sztywno i zwracałoby się ją tylko dla klientów/flow
             * oznaczonych przez "universal_signin_XXX".
             */

            if (AllowedClients.Contains(request.Client.ClientId) && request.GrantType == Constants.GrantTypes.AuthorizationCode)
            {
                string GenerateToken(Client client, CustomTokenResponseGeneratorConfig config, string sub, string sid, long timestamp, string ip)
                {
                    var token = new UniversalSignInToken(sub, sid, timestamp, ip, "n/a");
                    var crypted = token.Encrypt(client);

                    return $"{config.Uri}?token={crypted}";
                }

                var usi = new List<string>();

                foreach (var kvp in Database)
                {
                    var client = await clientStore.FindClientByIdAsync(kvp.Key);
                    var config = kvp.Value;

                    // TODO to jest trochę słabe, fajnie by było jakoś sensowniej to wyciągnąć
                    var idt = await tokenValidator.ValidateIdentityTokenAsync(response.IdentityToken, request.Client.ClientId, false).ConfigureAwait(false);

                    usi.Add(GenerateToken(
                        client,
                        config,
                        idt.Claims.First(c => c.Type == Constants.ClaimTypes.Subject).Value,
                        request.SessionId,
                        DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                        "some-ip"
                    ));
                }

                response.Custom.Add("universal_signin", usi);
            }

            return response;
        }


        public async Task<TokenResponse> X_GenerateAsync(ValidatedTokenRequest request, TokenResponse response)
        {
            await Task.Delay(1).ConfigureAwait(false); // TODO tmp

            if (request.GrantType == Constants.GrantTypes.AuthorizationCode && AllowedClients.Contains(request.Client.ClientId))
            {
                var universalSignInCodes = new List<string>();

                foreach (var kvp in Database)
                {
                    var client = await clientStore.FindClientByIdAsync(kvp.Key);
                    var config = kvp.Value;

                    universalSignInCodes.Add(await GenerateUniversalSignInResponseAsync(request, client));
                }

                response.Custom.Add("universal_sign_in_codes", universalSignInCodes);
            }

            return response;
        }

        private async Task<string> GenerateUniversalSignInResponseAsync(ValidatedTokenRequest request, Client client)
        {
            string key;
            var bytes = new byte[256];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(bytes);
                key = Convert.ToBase64String(bytes);
            }

            var code = new UniversalSignInCode
            {
                Client = client,
                Subject = request.Subject
            };

            await universalSignInCodeStore.StoreAsync(key, code).ConfigureAwait(false);

            return key;
        }
    }

    public class UniversalSignInToken
    {
        public string Sub { get; }
        public string Sid { get; }
        public long IssueTimestamp { get; }
        public string Ip { get; }
        public string UserAgent { get; }

        public UniversalSignInToken(string sub, string sid, long issueTimestamp, string ip, string userAgent)
        {
            Sub = sub;
            Sid = sid;
            IssueTimestamp = issueTimestamp;
            Ip = ip;
            UserAgent = userAgent;
        }

        public static UniversalSignInToken FromEncrypted(Client client, string input)
        {
            var key = client.ClientSecrets.First(s => s.Type == "universal_signin").Value + "abcdef";
            var data = StringCipher.Decrypt(input, key);

            var usit = JsonConvert.DeserializeObject<UniversalSignInToken>(data);

            return usit;
        }

        public string Encrypt(Client client)
        {
            var data = JsonConvert.SerializeObject(this);
            var key = client.ClientSecrets.First(s => s.Type == "universal_signin").Value + "abcdef";

            return StringCipher.Encrypt(data, key);
        }
    }

    // https://stackoverflow.com/questions/10168240/encrypting-decrypting-a-string-in-c-sharp
    // TODO zapewne zamienić na coś innego
    public static class StringCipher
    {
        // This constant is used to determine the keysize of the encryption algorithm in bits.
        // We divide this by 8 within the code below to get the equivalent number of bytes.
        private const int Keysize = 256;

        // This constant determines the number of iterations for the password bytes generation function.
        private const int DerivationIterations = 1000;

        public static string Encrypt(string plainText, string passPhrase)
        {
            // Salt and IV is randomly generated each time, but is preprended to encrypted cipher text
            // so that the same Salt and IV values can be used when decrypting.  
            var saltStringBytes = Generate256BitsOfRandomEntropy();
            var ivStringBytes = Generate256BitsOfRandomEntropy();
            var plainTextBytes = Encoding.UTF8.GetBytes(plainText);
            using (var password = new Rfc2898DeriveBytes(passPhrase, saltStringBytes, DerivationIterations))
            {
                var keyBytes = password.GetBytes(Keysize / 8);
                using (var symmetricKey = new RijndaelManaged())
                {
                    symmetricKey.BlockSize = 256;
                    symmetricKey.Mode = CipherMode.CBC;
                    symmetricKey.Padding = PaddingMode.PKCS7;
                    using (var encryptor = symmetricKey.CreateEncryptor(keyBytes, ivStringBytes))
                    {
                        using (var memoryStream = new MemoryStream())
                        {
                            using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                            {
                                cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
                                cryptoStream.FlushFinalBlock();
                                // Create the final bytes as a concatenation of the random salt bytes, the random iv bytes and the cipher bytes.
                                var cipherTextBytes = saltStringBytes;
                                cipherTextBytes = cipherTextBytes.Concat(ivStringBytes).ToArray();
                                cipherTextBytes = cipherTextBytes.Concat(memoryStream.ToArray()).ToArray();
                                memoryStream.Close();
                                cryptoStream.Close();
                                return Convert.ToBase64String(cipherTextBytes).Replace('+', '-').Replace('/', '_');
                            }
                        }
                    }
                }
            }
        }

        public static string Decrypt(string cipherText, string passPhrase)
        {
            // Get the complete stream of bytes that represent:
            // [32 bytes of Salt] + [32 bytes of IV] + [n bytes of CipherText]
            var cipherTextBytesWithSaltAndIv = Convert.FromBase64String(cipherText.Replace('-', '+').Replace('_', '/'));
            // Get the saltbytes by extracting the first 32 bytes from the supplied cipherText bytes.
            var saltStringBytes = cipherTextBytesWithSaltAndIv.Take(Keysize / 8).ToArray();
            // Get the IV bytes by extracting the next 32 bytes from the supplied cipherText bytes.
            var ivStringBytes = cipherTextBytesWithSaltAndIv.Skip(Keysize / 8).Take(Keysize / 8).ToArray();
            // Get the actual cipher text bytes by removing the first 64 bytes from the cipherText string.
            var cipherTextBytes = cipherTextBytesWithSaltAndIv.Skip((Keysize / 8) * 2).Take(cipherTextBytesWithSaltAndIv.Length - ((Keysize / 8) * 2)).ToArray();

            using (var password = new Rfc2898DeriveBytes(passPhrase, saltStringBytes, DerivationIterations))
            {
                var keyBytes = password.GetBytes(Keysize / 8);
                using (var symmetricKey = new RijndaelManaged())
                {
                    symmetricKey.BlockSize = 256;
                    symmetricKey.Mode = CipherMode.CBC;
                    symmetricKey.Padding = PaddingMode.PKCS7;
                    using (var decryptor = symmetricKey.CreateDecryptor(keyBytes, ivStringBytes))
                    {
                        using (var memoryStream = new MemoryStream(cipherTextBytes))
                        {
                            using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                            {
                                var plainTextBytes = new byte[cipherTextBytes.Length];
                                var decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
                                memoryStream.Close();
                                cryptoStream.Close();
                                return Encoding.UTF8.GetString(plainTextBytes, 0, decryptedByteCount);
                            }
                        }
                    }
                }
            }
        }

        private static byte[] Generate256BitsOfRandomEntropy()
        {
            var randomBytes = new byte[32]; // 32 Bytes will give us 256 bits.
            using (var rngCsp = new RNGCryptoServiceProvider())
            {
                // Fill the array with cryptographically secure random bytes.
                rngCsp.GetBytes(randomBytes);
            }
            return randomBytes;
        }
    }
}