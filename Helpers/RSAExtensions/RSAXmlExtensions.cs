using System;
using System.Security.Cryptography;
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

                if(modulus?.Value != null) pri.Modulus = Convert.FromBase64String(modulus.Value);
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

                if(modulus != null) pub.Modulus = Convert.FromBase64String(modulus.Value);
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
            var pri = rsa.ExportParameters(true);

            XElement privatElement = new("RSAKeyValue");
            //Modulus
            if (pri.Modulus != null)
            {
                XElement primodulus = new("Modulus", Convert.ToBase64String(pri.Modulus));
                privatElement.Add(primodulus);
            }
            //Exponent
            if (pri.Exponent != null) {
                XElement priexponent = new("Exponent", Convert.ToBase64String(pri.Exponent));
                privatElement.Add(priexponent);
            }
            //P
            if (pri.P != null)
            {
                XElement prip = new("P", Convert.ToBase64String(pri.P));
                privatElement.Add(prip);
            }
            //Q
            if (pri.Q != null)
            {
                XElement priq = new("Q", Convert.ToBase64String(pri.Q));
                privatElement.Add(priq);
            }
            //DP
            if (pri.DP != null)
            {
                XElement pridp = new("DP", Convert.ToBase64String(pri.DP));
                privatElement.Add(pridp);
            }
            //DQ
            if (pri.DQ != null)
            {
                XElement pridq = new("DQ", Convert.ToBase64String(pri.DQ));
                privatElement.Add(pridq);
            }

            //InverseQ
            if (pri.InverseQ != null)
            {
                XElement priinverseQ = new("InverseQ", Convert.ToBase64String(pri.InverseQ));
                privatElement.Add(priinverseQ);
            }
            //D
            if (pri.D != null)
            {
                XElement prid = new("D", Convert.ToBase64String(pri.D));
                privatElement.Add(prid);
            }

            return privatElement.ToString();
        }

        public static string ExportXmlPublicKey(this RSA rsa)
        {
            var pub = rsa.ExportParameters(false);

            XElement publicElement = new("RSAKeyValue");
            //Modulus
            if (pub.Modulus != null)
            {
                XElement pubmodulus = new("Modulus", Convert.ToBase64String(pub.Modulus));
                publicElement.Add(pubmodulus);
            }
            //Exponent
            if (pub.Exponent != null)
            {
                XElement pubexponent = new("Exponent", Convert.ToBase64String(pub.Exponent));
                publicElement.Add(pubexponent);
            }
            return publicElement.ToString();
        }
    }
}
