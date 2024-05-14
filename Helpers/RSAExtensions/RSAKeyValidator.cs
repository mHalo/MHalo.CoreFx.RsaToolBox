using MHalo.CoreFx.Helper;
using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using static Org.BouncyCastle.Bcpg.Attr.ImageAttrib;

namespace MHalo.CoreFx.RsaToolBox.Helpers.RSAExtensions
{
    public class RSAKeyValidator
    {
        public static bool IsValidPublicKey(string publicKey, out RSAKeyType keyType)
        {
            RSACryptoServiceProvider rsaPrivateKey = new RSACryptoServiceProvider();
            try
            {
                rsaPrivateKey.ImportRSAPublicKey(Convert.FromBase64String(publicKey), out _);
                keyType = RSAKeyType.Pkcs1;
                return rsaPrivateKey.PublicOnly;
            }
            catch
            {
                try
                {
                    rsaPrivateKey.ImportPkcs8PublicKey(Convert.FromBase64String(publicKey));
                    keyType = RSAKeyType.Pkcs8;
                    return rsaPrivateKey.PublicOnly;
                }
                catch
                {
                    try
                    {
                        rsaPrivateKey.ImportXmlPublicKey(publicKey);
                        keyType = RSAKeyType.Xml;
                        return rsaPrivateKey.PublicOnly;
                    }
                    catch
                    {
                        keyType = RSAKeyType.Pkcs1;
                        return false;
                    }
                }
            }
        }
        public static bool IsValidPrivateKey(string privateKey, out RSAKeyType keyType)
        {
            RSACryptoServiceProvider rsaPrivateKey = new RSACryptoServiceProvider();
            try
            {
                rsaPrivateKey.ImportRSAPrivateKey(Convert.FromBase64String(privateKey), out _);
                keyType = RSAKeyType.Pkcs1;
                return !rsaPrivateKey.PublicOnly;
            }
            catch
            {
                try
                {
                    rsaPrivateKey.ImportPkcs8PrivateKey(Convert.FromBase64String(privateKey), out _);
                    keyType = RSAKeyType.Pkcs8;
                    return !rsaPrivateKey.PublicOnly;
                }
                catch
                {
                    try
                    {
                        rsaPrivateKey.ImportXmlPrivateKey(privateKey);
                        keyType = RSAKeyType.Xml;
                        return !rsaPrivateKey.PublicOnly;
                    }
                    catch
                    {
                        keyType = RSAKeyType.Pkcs1;
                        return false;
                    }
                }
            }
        }
    }
}
