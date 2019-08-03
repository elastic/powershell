using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Elastic
{
    /// <summary>
    /// Handlers for certificate validation
    /// </summary>
    public class ServerCertificateValidation
    {
        /// <summary>
        /// Skip certificate validation
        /// </summary>
        public static RemoteCertificateValidationCallback AllowAll()
        {
            return new RemoteCertificateValidationCallback(delegate (object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors policyErrors) { return true; });
        }
    }
}