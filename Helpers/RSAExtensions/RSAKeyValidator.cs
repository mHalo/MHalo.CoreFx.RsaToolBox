using MHalo.CoreFx.Helper;
using Org.BouncyCastle.Asn1.X9;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using static MHalo.CoreFx.Helper.RSAHelper;
using System.Linq;
using System.Linq.Expressions;

namespace MHalo.CoreFx.RsaToolBox.Helpers.RSAExtensions
{
    public class RSAKeyValidator
    {
        public static bool IsValidPublicKey(string publicKey, out RSAKeyType? keyType)
        {
            keyType = null;
            publicKey = PemFormatUtil.RemoveFormat(publicKey);
            RSACryptoServiceProvider rsaPrivateKey = new ();
            try
            {
                rsaPrivateKey.ImportPublicKey(RSAKeyType.Pkcs1, publicKey);
                keyType = RSAKeyType.Pkcs1;
                return rsaPrivateKey.PublicOnly;
            }
            catch
            {
                try
                {
                    rsaPrivateKey.ImportPublicKey(RSAKeyType.Pkcs8, publicKey);
                    keyType = RSAKeyType.Pkcs8;
                    return rsaPrivateKey.PublicOnly;
                }
                catch
                {
                    try
                    {
                        XmlDocument xmlDoc = new XmlDocument();
                        xmlDoc.LoadXml(publicKey);
                        if (xmlDoc.DocumentElement!.Name.Equals("RSAKeyValue"))
                        {
                            var rootNode = xmlDoc.DocumentElement!;
                            // 检查是否包含Modulus和Exponent元素，这两个是公钥和私钥都必须有的
                            XmlNode? modulusNode = rootNode.SelectSingleNode("Modulus");
                            XmlNode? exponentNode = rootNode.SelectSingleNode("Exponent");
                            if (modulusNode != null && exponentNode != null && rootNode.ChildNodes.Count == 2)
                            {
                                keyType = RSAKeyType.Xml;
                                return true;
                            }
                        }
                    }
                    catch { }
                    return false;
                }
            }
        }
        public static bool IsValidPrivateKey(string privateKey, out RSAKeyType? keyType)
        {
            keyType = null;
            privateKey = PemFormatUtil.RemoveFormat(privateKey);
            RSACryptoServiceProvider rsaPrivateKey = new ();
            try
            {
                rsaPrivateKey.ImportPrivateKey(RSAKeyType.Pkcs1, privateKey);
                keyType = RSAKeyType.Pkcs1;
                return !rsaPrivateKey.PublicOnly;
            }
            catch
            {
                try
                {
                    rsaPrivateKey.ImportPrivateKey(RSAKeyType.Pkcs8, privateKey);
                    keyType = RSAKeyType.Pkcs8;
                    return !rsaPrivateKey.PublicOnly;
                }
                catch
                {
                    try
                    {
                        RSAParameters rsaParams = XMLRSAKeyManager.GetRSAPrivateParameters(privateKey);
                        keyType = RSAKeyType.Xml;
                        return true;
                    }
                    catch { }
                    return false;
                }
            }
        }
    }
}
