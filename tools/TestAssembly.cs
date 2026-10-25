using System;
public class Program {
    public static void Main(string[] args) {
        Console.WriteLine("[TestAssembly] Hello from fileless .NET loader!");
        Console.WriteLine("[TestAssembly] Arguments: " + string.Join(", ", args));
        Console.WriteLine("[TestAssembly] AppDomain: " + AppDomain.CurrentDomain.FriendlyName);
        Console.WriteLine("[TestAssembly] CLR Version: " + Environment.Version);
        Console.WriteLine("[TestAssembly] SUCCESS - Assembly executed in memory!");
    }
}