using System;
using System.Collections;
using System.ComponentModel.Design;
using System.Security.Cryptography;
using System.Text;
using CommandLine;

namespace BinaryToPowershellScript
{
    public class Options
    {
        [Option('i', "inputs", Required = true, HelpText = "Specify the input file(s) to process, you can use also a wildcard pattern")]
        public IEnumerable<String> Inputs { get; set; }

        [Option('o', "outputfolder", Required = false, HelpText = "Specify the output folder where all the powershell scripts will be generated")]
        public String OutputFolder { get; set; }

        [Option('b', "base64", Required = false, HelpText = "Specify the base64 file format for the powershell script(s)")]
        public bool Base64 { get; set; }

        [Option('s', "single", Required = false, HelpText = "Specify to create just a single script file for all input files")]
        public bool SingleFile { get; set; }

        [Option('r', "randomizevariables", Required = false, HelpText = "Specify to create random variables names in the script")]
        public bool Randomize { get; set; }

        [Option('p', "password", Required = false, HelpText = "Specify the password used to encrypt data with AES")]
        public String Password { get; set; }

    }


    class Program
    {
        const int KEYSIZE = 256;

        public static void Main(string[] args)
        {
            Parser.Default.ParseArguments<Options>(args).WithParsed<Options>(o => CreateScript(o));
        }


        public static byte[] EncryptBytes(byte[] input, string password)
        {
            var pbkdf2DerivedBytes = new Rfc2898DeriveBytes(password, 16, 2000);

            using (var AES = Aes.Create())
            {
                AES.KeySize = KEYSIZE;
                AES.Key = pbkdf2DerivedBytes.GetBytes(KEYSIZE / 8);
                AES.Mode = CipherMode.CBC;
                AES.Padding = PaddingMode.PKCS7;

                using (MemoryStream memoryStream = new MemoryStream())
                {
                    CryptoStream cryptoStream = new CryptoStream(memoryStream, AES.CreateEncryptor(), CryptoStreamMode.Write);

                    memoryStream.Write(pbkdf2DerivedBytes.Salt, 0, 16);  // 16 bytes of SALT for PBKDF2 derivation function, must not be encrypted
                    memoryStream.Write(AES.IV, 0, 16);  // IV is always 128 bits, must not be encrypted
                    cryptoStream.Write(input, 0, input.Length);
                    cryptoStream.FlushFinalBlock();

                    Console.WriteLine($"Password {password} Salt {BitConverter.ToString(pbkdf2DerivedBytes.Salt)} IV {BitConverter.ToString(AES.IV)} Key {BitConverter.ToString(AES.Key)} Input {BitConverter.ToString(input)} ActualPosition {memoryStream.Length}");
                    return memoryStream.ToArray();
                }
            }
        }


        private static StringBuilder CreateScriptHeader(Options o)
        {
            var script = new StringBuilder();
            script.Append($"param ([parameter(Mandatory={(String.IsNullOrEmpty(o.Password)?"$false":"$true")})] [String] $Password)\n\n");
            script.Append("$setContentHelp = (help Set-Content) | Out-String\nif ($setContentHelp.Contains(\"AsByteStream\")) { $core = $true } else { $core = $false }\n\n");
    
            script.Append(@$"function decryptBytes {{
    [OutputType([byte[]])]
    Param (
		[parameter(Mandatory=$true)] [System.Byte[]] $bytes,
		[parameter(Mandatory=$true)] [System.String] $password
	) 

    # Split IV and encrypted data
    $PBKDF2Salt = New-Object Byte[] 16
    $IV = New-Object Byte[] 16
    $EncryptedData = New-Object Byte[] ($bytes.Length-32)
    
    [System.Array]::Copy($bytes, 0, $PBKDF2Salt, 0, 16)
    [System.Array]::Copy($bytes, 16, $IV, 0, 16)
    [System.Array]::Copy($bytes, 32, $EncryptedData, 0, $bytes.Length-32)

	# Generate PBKDF2 from Salt and Password
	$PBKDF2 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($password, $PBKDF2Salt, 2000)

	# Setup our decryptor
	$AES = [Security.Cryptography.Aes]::Create()
	$AES.KeySize = {KEYSIZE}
	$AES.Key = $PBKDF2.GetBytes({KEYSIZE / 8})
	$AES.IV = $IV
	$AES.Mode = [System.Security.Cryptography.CipherMode]::CBC
	$AES.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

	Write-Host ""Password $password""
	Write-Host ""KEY: $([System.BitConverter]::ToString($AES.Key))""
	Write-Host ""IV: $([System.BitConverter]::ToString($AES.IV))""
	Write-Host ""EncryptedData: $([System.BitConverter]::ToString($EncryptedData))""

	$Dec = $AES.CreateDecryptor()

	$EncryptedMemoryStream = New-Object System.IO.MemoryStream @(,$EncryptedData)
	$DecryptedMemoryStream = New-Object System.IO.MemoryStream
	$CryptoStream = New-Object System.Security.Cryptography.CryptoStream($EncryptedMemoryStream, $Dec, [System.Security.Cryptography.CryptoStreamMode]::Read)

	$CryptoStream.CopyTo($DecryptedMemoryStream)
	
	$result = $DecryptedMemoryStream.ToArray()
	Write-Host ""DecryptedData: $([System.BitConverter]::ToString($result))""

	,$result
}}");
            script.Append("\n\n");

            return script;
        }



        public static void CreateScript(Options o)
        {
            if (String.IsNullOrEmpty(o.OutputFolder))
                o.OutputFolder = Directory.GetCurrentDirectory();

            StringBuilder script = CreateScriptHeader(o);

            var outputFile = Path.Combine(o.OutputFolder, $"SingleScript{(o.Base64 ? "_base64" : String.Empty)}.ps1");

            foreach (var input in o.Inputs)
                foreach (var file in Directory.GetFileSystemEntries(Path.GetDirectoryName(input), Path.GetFileName(input)))
                {

                    if (!o.SingleFile)
                    {
                        script = CreateScriptHeader(o);

                        outputFile = Path.Combine(o.OutputFolder, $"{Path.GetFileName(file).Replace(".", "_")}_script{(o.Base64 ? "_base64" : String.Empty)}.ps1");
                    }

                    Console.WriteLine($"Scripting file {file} {(!o.SingleFile ? $"into {outputFile}..." : String.Empty)}");

                    var bytes = String.IsNullOrEmpty(o.Password) ? File.ReadAllBytes(file) : EncryptBytes(File.ReadAllBytes(file), o.Password);

                    if (o.Base64)
                    {
                        script.Append($"[byte[]] $bytes = [Convert]::FromBase64String('{Convert.ToBase64String(bytes)}')");
                    }
                    else
                    {
                        script.Append("[byte[]] $bytes = ");

                        foreach (var b in bytes)
                            script.Append($"0x{b.ToString("X2")},");

                        script.Length--;
                    }

                    var bytesString = String.IsNullOrEmpty(o.Password) ? "$bytes" : "(decryptBytes $bytes $Password)";
                    script.Append($"\nif ($core) {{ Set-Content -Path {Path.GetFileName(file)} -Value {bytesString} -AsByteStream }} else {{ Set-Content {Path.GetFileName(file)} -Value {bytesString} -Encoding Byte }}{(o.SingleFile ? "\n\n" : String.Empty)}");

                    if (!o.SingleFile)
                        File.WriteAllText(outputFile, script.ToString());
                }

            if (o.SingleFile)
            {
                Console.WriteLine($"Creating single script file {outputFile}...");
                File.WriteAllText(outputFile, script.ToString());
            }
        }

    }
}