using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

class SimpleServer {
    static void Main(string[] args) {
        int port = 8443;
        string dir = @"C:\Users\chems\Desktop\01_Cyber\Outils\CLRLoader\tools";
        var listener = new TcpListener(IPAddress.Loopback, port);
        listener.Start();
        Console.WriteLine("Listening on 127.0.0.1:" + port + " serving " + dir);
        while (true) {
            try {
                TcpClient client = listener.AcceptTcpClient();
                NetworkStream stream = client.GetStream();
                stream.ReadTimeout = 5000;
                byte[] buf = new byte[4096];
                int read = stream.Read(buf, 0, buf.Length);
                string request = Encoding.ASCII.GetString(buf, 0, read);
                string firstLine = request.Split(new[]{"\r\n"}, StringSplitOptions.None)[0];
                Console.WriteLine("Request: " + firstLine);
                string[] parts = firstLine.Split(' ');
                string filename = parts[1].TrimStart('/');
                string filePath = Path.Combine(dir, filename);
                if (File.Exists(filePath)) {
                    byte[] data = File.ReadAllBytes(filePath);
                    string header = "HTTP/1.1 200 OK\r\nContent-Length: " + data.Length + "\r\nConnection: close\r\n\r\n";
                    byte[] headerBytes = Encoding.ASCII.GetBytes(header);
                    stream.Write(headerBytes, 0, headerBytes.Length);
                    stream.Write(data, 0, data.Length);
                    stream.Flush();
                    Console.WriteLine("  Served " + data.Length + " bytes");
                } else {
                    string resp = "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\nNot Found";
                    byte[] respBytes = Encoding.ASCII.GetBytes(resp);
                    stream.Write(respBytes, 0, respBytes.Length);
                    Console.WriteLine("  404: " + filePath);
                }
                client.Close();
            } catch (Exception ex) {
                Console.WriteLine("Error: " + ex.Message);
            }
        }
    }
}
