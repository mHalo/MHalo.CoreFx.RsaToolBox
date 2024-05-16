using System;
using System.Data.SqlTypes;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.Xml.Linq;

namespace MHalo.CoreFx.Helper
{
    public static class RSAXmlExtensions
    {
        public static void ImportXmlPrivateKey(this RSA rsa, string privateKey)
        {
            var pri = new RSAParameters();
            try
            {
                XElement root = XElement.Parse(privateKey);
                //Modulus
                var modulus = root.Element("Modulus");

                //Exponent
                var exponent = root.Element("Exponent");
                //P
                var p = root.Element("P");
                //Q
                var q = root.Element("Q");
                //DP
                var dp = root.Element("DP");
                //DQ
                var dq = root.Element("DQ");
                //InverseQ
                var inverseQ = root.Element("InverseQ");
                //D
                var d = root.Element("D");

                if (modulus?.Value != null) pri.Modulus = Convert.FromBase64String(modulus.Value);
                if (exponent?.Value != null) pri.Exponent = Convert.FromBase64String(exponent.Value);
                if (p?.Value != null) pri.P = Convert.FromBase64String(p.Value);
                if (q?.Value != null) pri.Q = Convert.FromBase64String(q.Value);
                if (dp?.Value != null) pri.DP = Convert.FromBase64String(dp.Value);
                if (dq?.Value != null) pri.DQ = Convert.FromBase64String(dq.Value);
                if (inverseQ?.Value != null) pri.InverseQ = Convert.FromBase64String(inverseQ.Value);
                if (d?.Value != null) pri.D = Convert.FromBase64String(d.Value);

                rsa.ImportParameters(pri);
            }
            catch (Exception e)
            {
                throw new Exception("The xml private key is incorrect.", e);
            }
        }

        public static void ImportXmlPublicKey(this RSA rsa, string publicKey)
        {
            var pub = new RSAParameters();
            try
            {
                XElement root = XElement.Parse(publicKey);
                //Modulus
                var modulus = root.Element("Modulus");
                //Exponent
                var exponent = root.Element("Exponent");

                if (modulus != null) pub.Modulus = Convert.FromBase64String(modulus.Value);
                if (exponent != null) pub.Exponent = Convert.FromBase64String(exponent.Value);

                rsa.ImportParameters(pub);
            }
            catch (Exception e)
            {
                throw new Exception("The xml public key is incorrect.", e);
            }
        }

        public static string ExportXmlPrivateKey(this RSA rsa)
        {
            return rsa.ToXmlString(true);
        }

        public static string ExportXmlPublicKey(this RSA rsa)
        {
            return rsa.ToXmlString(false);
        }
    }
}
