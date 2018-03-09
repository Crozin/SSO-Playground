
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Owin.Security;

namespace SharedNet
{


    public class DummyCertificateValidator : ICertificateValidator
    {
        public bool Validate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }
    }
}
