using System;
using System.IO;
using System.Security.Cryptography;
using MHalo.CoreFx.Helper.RSAExtensions;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace MHalo.CoreFx.Helper
{
    /// <summary>
    /// RSA export key extensions.Support XML format import and export and PEM format.
    /// </summary>
    public static class RSAKeyExtensions
    {
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
        
    }
}
