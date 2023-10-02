using System;
using System.ComponentModel.Design;
using System.Text;
using CommandLine;

namespace BinaryToPowershellScript
{
    public class Options
    {
        [Option('i', "inputs", Required = true, HelpText = "Specify the input file(s) to process")]
        public IEnumerable<String> Inputs { get; set; }

        [Option('o', "outputfolder", Required = false, HelpText = "Specify the output folder")]
        public String OutputFolder { get; set; }

        [Option('b', "base64", Required = false, HelpText = "Specify the base64 file format")]
        public bool Base64 { get; set; }

        [Option('s', "single", Required = false, HelpText = "Specify to create just a single script file for all input files")]
        public bool SingleFile { get; set; }

    }

    class Program
    {
        public static void Main(string[] args)
        {
            Parser.Default.ParseArguments<Options>(args).WithParsed<Options>(o => CreateScript(o));
        }


        public static void CreateScript(Options o)
        {
            if (String.IsNullOrEmpty(o.OutputFolder))
                o.OutputFolder = Directory.GetCurrentDirectory();

            var script = new StringBuilder();
            script.Append("$setContentHelp = (help Set-Content) | Out-String\nif ($setContentHelp.Contains(\"AsByteStream\")) { $core = $true } else { $core = $false }\n\n");

            var outputFile = Path.Combine(o.OutputFolder, $"SingleScript{(o.Base64 ? "_base64" : String.Empty)}.ps1");

            foreach (var input in o.Inputs)
                foreach (var file in Directory.GetFileSystemEntries(Path.GetDirectoryName(input), Path.GetFileName(input)))
                {

                    if (!o.SingleFile)
                    {
                        script = new StringBuilder();
                        script.Append("$setContentHelp = (help Set-Content) | Out-String\nif ($setContentHelp.Contains(\"AsByteStream\")) { $core = $true } else { $core = $false }\n");

                        outputFile = Path.Combine(o.OutputFolder, $"{Path.GetFileName(file).Replace(".", "_")}_script{(o.Base64 ? "_base64" : String.Empty)}.ps1");
                    }

                    Console.WriteLine($"Scripting file {file} {(!o.SingleFile ? $"into {outputFile}..." : String.Empty)}");

                    var bytes = File.ReadAllBytes(file);

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

                    script.Append($"\nif ($core) {{ Set-Content -Path {Path.GetFileName(file)} -Value $bytes -AsByteStream }} else {{ Set-Content {Path.GetFileName(file)} -Value $bytes -Encoding Byte }}{(o.SingleFile?"\n\n":String.Empty)}");

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