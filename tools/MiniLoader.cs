using System;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Reflection;

public class Loader
{
    public static int Execute(string args)
    {
        try
        {
            string[] parts = args.Split(new char[] { '|' });
            string mapName = parts[0];
            int size = int.Parse(parts[1]);

            byte[] asmBytes = new byte[size];
            using (var mmf = MemoryMappedFile.OpenExisting(mapName))
            using (var accessor = mmf.CreateViewAccessor(0, size, MemoryMappedFileAccess.Read))
            {
                accessor.ReadArray(0, asmBytes, 0, size);
            }

            Assembly asm = Assembly.Load(asmBytes);

            string[] asmArgs = new string[parts.Length - 2];
            if (asmArgs.Length > 0)
                Array.Copy(parts, 2, asmArgs, 0, asmArgs.Length);

            MethodInfo entry = asm.EntryPoint;
            if (entry != null)
            {
                if (entry.GetParameters().Length > 0)
                    entry.Invoke(null, new object[] { asmArgs });
                else
                    entry.Invoke(null, null);
            }
            return 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine("[!] MiniLoader error: " + ex.ToString());
            return 1;
        }
    }
}
