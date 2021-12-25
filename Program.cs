using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Whois;

namespace whois
{
    class Program
    {
        static async Task Main()
        {

            var listener = new HttpListener();
            listener.Prefixes.Add("http://127.0.0.1:5000/");
            listener.Start();

            var appCts = new CancellationTokenSource();

            Console.CancelKeyPress += (o, ev) => { appCts.Cancel(); ev.Cancel = true; };
            appCts.Token.Register(() => listener.Stop());

            while (!appCts.IsCancellationRequested)
            {
                try
                {
                    var ctx = await listener.GetContextAsync();
                    _ = ProcessQuery(ctx, appCts.Token);
                }
                catch (HttpListenerException)
                {
                    // happens on cancel
                }
            }
        }

        static async Task ProcessQuery(HttpListenerContext ctx, CancellationToken ct)
        {
            var req = ctx.Request;
            var resp = ctx.Response;

            Console.WriteLine($"{req.HttpMethod}: {req.RawUrl}");
            if (req.ContentLength64 == 0)
            {
                resp.StatusCode = 406;
                resp.StatusDescription = "The content can't be empty";
            }
            else
            {
                var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);

                cts.CancelAfter(3000);

                using var reader = new StreamReader(req.InputStream, Encoding.UTF8);
                var query = await reader.ReadToEndAsync();
                Console.WriteLine($"Starting whois for {query}");
                var lookup = new WhoisLookup();

                var result = await lookup.LookupAsync(query);

                cts.Token.ThrowIfCancellationRequested();

                Console.WriteLine("Whois query for {0} completed with status {1}", query, result.Status);
                using var writer = new StreamWriter(ctx.Response.OutputStream, Encoding.UTF8);
                writer.WriteLine(result.Content);
            }
            resp.Close();
        }
    }
}
