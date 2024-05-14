using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MHalo.CoreFx.Helper
{
    public class IoHelper
    {
        /// <summary>
        /// 判断路径为文件夹，且文件夹存在
        /// </summary>
        /// <param name="filePath"></param>
        /// <returns></returns>
        public static bool IsDirectory(string filePath)
        {
            return Directory.Exists(filePath);
        }

        /// <summary>
        /// 判断路径是否是文件,且文件存在
        /// </summary>
        /// <param name="filePath"></param>
        /// <returns></returns>
        public static bool IsFile(string filePath)
        {
            return File.Exists(filePath);
        }

        /// <summary>
        /// 创建文件
        /// <para>当文件存在时，将会覆盖创建</para>
        /// <para>当路径中某个文件夹不存在时，将会创建对应的文件夹</para>
        /// </summary>
        /// <param name="physicalFilePath">物理文件路径</param>
        /// <param name="content">文件内容</param>

        public static void CreateFile(string physicalFilePath, string content)
        {
            var directoryName = Path.GetDirectoryName(physicalFilePath);
            if (!Directory.Exists(directoryName) && directoryName is not null)
            {
                Directory.CreateDirectory(directoryName);
            }
            using StreamWriter sw = File.CreateText(physicalFilePath);
            sw.Write(content);
        }

    }
}
