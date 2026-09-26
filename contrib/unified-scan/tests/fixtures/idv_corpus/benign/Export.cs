using System;
using System.IO;

class Export {
    static void Main(string[] args) {
        var lines = File.ReadAllLines(args[0]);
        File.WriteAllLines(args[1], lines);
        Console.WriteLine("rows: " + lines.Length);
    }
}
