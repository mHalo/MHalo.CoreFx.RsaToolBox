using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System.IO;
using System.Security.Cryptography;
using System.Xml;

namespace MHalo.CoreFx.Helper.RSAExtensions
{
    /// <summary>
    /// RSA export key extensions.Support XML format import and export and PEM format.
    /// </summary>
    public static class RSAKeyExtensions
    {
        #region ImportKey

        public static void ImportPkcs8PublicKey(this RSA rsa, byte[] publicKey)
        {
            RsaKeyParameters publicKeyParam = (RsaKeyParameters)PublicKeyFactory.CreateKey(publicKey);
            var pub = new RSAParameters
            {
                Modulus = publicKeyParam.Modulus.ToByteArrayUnsigned(),
                Exponent = publicKeyParam.Exponent.ToByteArrayUnsigned()
            };
            rsa.ImportParameters(pub);
        }
        /// <summary>
        /// Export RSA private key
        /// </summary>
        /// <param name="rsa"></param>
        /// <param name="type"></param>
        /// <param name="privateKey"></param>
        /// <param name="isPem">当密钥类型为Xml时，此参数不起效</param>
        /// <returns></returns>
        public static void ImportPrivateKey(this RSA rsa, RSAKeyType type, string privateKey, bool isPem = false)
        {
            if (isPem)
            {
                privateKey = PemFormatUtil.RemoveFormat(privateKey);
            }
            switch (type)
            {
                case RSAKeyType.Pkcs1:
                    rsa.ImportRSAPrivateKey(Convert.FromBase64String(privateKey), out _);
                    break;
                case RSAKeyType.Pkcs8:
                    rsa.ImportPkcs8PrivateKey(Convert.FromBase64String(privateKey), out _);
                    break;
                case RSAKeyType.Xml:
                    rsa.ImportXmlPrivateKey(privateKey);
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(type), type, null);
            }
        }
        /// <summary>
        /// Export RSA public key
        /// </summary>
        /// <param name="rsa"></param>
        /// <param name="type"></param>
        /// <param name="publicKey"></param>
        /// <param name="isPem">当密钥类型为Xml时，此参数不起效</param>
        /// <returns></returns>
        public static void ImportPublicKey(this RSA rsa, RSAKeyType type, string publicKey, bool isPem = false)
        {
            if (isPem)
            {
                publicKey = PemFormatUtil.RemoveFormat(publicKey);
            }

            switch (type)
            {
                case RSAKeyType.Pkcs1:
                    rsa.ImportRSAPublicKey(Convert.FromBase64String(publicKey), out _);
                    break;
                case RSAKeyType.Pkcs8:
                    rsa.ImportPkcs8PublicKey(Convert.FromBase64String(publicKey));
                    break;
                case RSAKeyType.Xml:
                    rsa.ImportXmlPublicKey(publicKey);
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(type), type, null);
            }
        }

        #endregion

        #region ExportKey
        /// <summary>
        /// Export RSA private key
        /// </summary>
        /// <param name="rsa"></param>
        /// <param name="type"></param>
        /// <param name="usePemFormat">当密钥类型为Xml时，此参数不起效</param>
        /// <returns></returns>
        public static string ExportPrivateKey(this RSA rsa, RSAKeyType type, bool usePemFormat = false)
        {
            var key = type switch
            {
                RSAKeyType.Pkcs1 => Convert.ToBase64String(rsa.ExportRSAPrivateKey()),
                RSAKeyType.Pkcs8 => Convert.ToBase64String(rsa.ExportPkcs8PrivateKey()),
                RSAKeyType.Xml => rsa.ExportXmlPrivateKey(),
                _ => string.Empty
            };

            if (usePemFormat && type != RSAKeyType.Xml)
            {
                key = PemFormatUtil.GetPrivateKeyFormat(type, key);
            }

            return key;
        }
        /// <summary>
        /// Export RSA public key
        /// </summary>
        /// <param name="rsa"></param>
        /// <param name="type"></param>
        /// <param name="usePemFormat">当密钥类型为Xml时，此参数不起效</param>
        /// <returns></returns>
        public static string ExportPublicKey(this RSA rsa, RSAKeyType type, bool usePemFormat = false)
        {
            var key = type switch
            {
                RSAKeyType.Pkcs1 => Convert.ToBase64String(rsa.ExportRSAPublicKey()),
                RSAKeyType.Pkcs8 => Convert.ToBase64String(rsa.ExportPkcs8PublicKey()),
                RSAKeyType.Xml => rsa.ExportXmlPublicKey(),
                _ => string.Empty
            };

            if (usePemFormat && type != RSAKeyType.Xml)
            {
                key = PemFormatUtil.GetPublicKeyFormat(type, key);
            }

            return key;
        }
        public static byte[] ExportPkcs8PublicKey(this RSA rsa)
        {
            var pub = rsa.ExportParameters(false);
            var rsaKeyParameters = new RsaKeyParameters(false, new BigInteger(1, pub.Modulus), new BigInteger(1, pub.Exponent));
            var sw = new StringWriter();
            var pWrt = new PemWriter(sw);
            pWrt.WriteObject(rsaKeyParameters);
            pWrt.Writer.Close();
            return Convert.FromBase64String(PemFormatUtil.RemoveFormat(sw.ToString()));
        }
        #endregion

        #region CreateAsymmetricKeyParameter
        private static class XMLRSAKeyManager
        {
            private static Dictionary<string, RSAParameters> cachedRSAParameters = new();
            public static RSAParameters GetRSAPrivateParameters(string privateKeyContent)
            {
                if (cachedRSAParameters.TryGetValue(privateKeyContent, out RSAParameters rsaParams))
                {
                    return rsaParams;
                }
                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                {
                    rsa.FromXmlString(privateKeyContent);
                    rsaParams = rsa.ExportParameters(true);
                    cachedRSAParameters[privateKeyContent] = rsaParams;
                }
                return rsaParams;
            }
            public static RSAParameters GetRSAPublicParameters(string publicKeyContent)
            {
                if (cachedRSAParameters.TryGetValue(publicKeyContent, out RSAParameters rsaParams))
                {
                    return rsaParams;
                }
                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                {
                    rsa.FromXmlString(publicKeyContent);
                    rsaParams = rsa.ExportParameters(false);
                    cachedRSAParameters[publicKeyContent] = rsaParams;
                }
                return rsaParams;
            }
        }

        internal static AsymmetricKeyParameter CreateAsymmetricPublicKeyParameter(RSAKeyType keyType, string publicKeyContent)
        {
            AsymmetricKeyParameter publicKeyParameter;
            if (keyType.Equals(RSAKeyType.Pkcs1))
            {
                publicKeyContent = PemFormatUtil.RemoveFormat(publicKeyContent);
                byte[] keyByte = Convert.FromBase64String(publicKeyContent);
                RsaPublicKeyStructure publicKeyStructure = RsaPublicKeyStructure.GetInstance(Asn1Object.FromByteArray(keyByte));
                // 创建RSA公钥参数
                publicKeyParameter = new RsaKeyParameters(false, publicKeyStructure.Modulus, publicKeyStructure.PublicExponent);

            }
            else if (keyType.Equals(RSAKeyType.Pkcs8))
            {
                publicKeyContent = PemFormatUtil.RemoveFormat(publicKeyContent);
                byte[] keyByte = Convert.FromBase64String(publicKeyContent);
                publicKeyParameter = PublicKeyFactory.CreateKey(keyByte);
            }
            else
            {
                // 获取RSA参数
                RSAParameters rsaParams = XMLRSAKeyManager.GetRSAPublicParameters(publicKeyContent);
                // 创建RsaKeyParameters
                publicKeyParameter = new RsaKeyParameters(false, new BigInteger(1, rsaParams.Modulus), new BigInteger(1, rsaParams.Exponent));
            }
            return publicKeyParameter;
        }

        internal static AsymmetricKeyParameter CreateAsymmetricPrivateKeyParameter(RSAKeyType keyType, string privateKeyContent)
        {
            AsymmetricKeyParameter privateKeyParameter;
            if (keyType.Equals(RSAKeyType.Pkcs1))
            {
                privateKeyContent = PemFormatUtil.RemoveFormat(privateKeyContent);
                byte[] keyByte = Convert.FromBase64String(privateKeyContent);

                RsaPrivateKeyStructure privateKeyStructure = RsaPrivateKeyStructure.GetInstance(Asn1Object.FromByteArray(keyByte));
                // 创建RSA公钥参数
                privateKeyParameter = new RsaKeyParameters(true, privateKeyStructure.Modulus, privateKeyStructure.PrivateExponent);

            }
            else if (keyType.Equals(RSAKeyType.Pkcs8))
            {
                privateKeyContent = PemFormatUtil.RemoveFormat(privateKeyContent);
                byte[] keyByte = Convert.FromBase64String(privateKeyContent);
                privateKeyParameter = PrivateKeyFactory.CreateKey(keyByte);
            }
            else
            {
                // 获取RSA参数
                RSAParameters rsaParams = XMLRSAKeyManager.GetRSAPrivateParameters(privateKeyContent);
                // 创建RsaKeyParameters
                privateKeyParameter = new RsaKeyParameters(true, new BigInteger(1, rsaParams.Modulus), new BigInteger(1, rsaParams.D));
            }
            return privateKeyParameter;
        }
        #endregion



        #region KeyValidator

        public static bool IsValidPublicKey(string publicKey, out RSAKeyType? keyType)
        {
            keyType = null;
            publicKey = PemFormatUtil.RemoveFormat(publicKey);
            RSACryptoServiceProvider rsaPrivateKey = new();
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
            RSACryptoServiceProvider rsaPrivateKey = new();
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
                        RSAParameters rsaParams = RSAKeyExtensions.XMLRSAKeyManager.GetRSAPrivateParameters(privateKey);
                        keyType = RSAKeyType.Xml;
                        return true;
                    }
                    catch { }
                    return false;
                }
            }
        }

        #endregion

    }
}
