using System;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;


using Blake3;

namespace FileOnce;
static class Program {
    // ---------- 配置 ----------
    const int TokenLength = 37;
    static readonly ulong[] TokenIndexes = new ulong[TokenLength];
    static ReadOnlySpan<char> TokenChars() => "ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789";
    const long MaxFileSize = 128 * 1024 * 1024; // 128 MB
    static readonly byte[] FileBuffer = new byte[MaxFileSize + 16];
    static readonly byte[] AES_Buffer = new byte[MaxFileSize];
    static readonly char[] InvalidFileNameChars = Path.GetInvalidFileNameChars();
    static volatile bool wrote = false;
    static string root = ".";
    static long start_time = 0, data_amount = 0;
    const byte bytes_aes_key = 32;
    const byte bytes_aes_nonce = 12;
    const byte bytes_aes_tag = 16;
    static readonly byte[] aes_key_nonce_tag = new byte[bytes_aes_key + bytes_aes_nonce + bytes_aes_tag];

    static readonly HashSet<string> ReservedFileNames = new(StringComparer.OrdinalIgnoreCase) {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
        ".", "..", ""
    };

    static bool IsReservedFileName(string fileName) {
        // 提取不带扩展名的部分（如 CON.txt → CON）
        string nameWithoutExt = Path.GetFileNameWithoutExtension(fileName);
        return ReservedFileNames.Contains(nameWithoutExt);
    }

    static async Task Main(string[] args) {
        Console.WriteLine();
        if (args.Length == 0) {
            Console.WriteLine("用法: FileOnce <http前缀1> [http前缀2] ...");
            Console.WriteLine("示例: FileOnce http://127.0.0.1:6543/fileonce/ http://8.9.10.11:80/outside/");
            return;
        }

        var basePrefixes = args.Select(p => p.EndsWith("/") ? p : p + "/").ToArray();
        foreach (var b in basePrefixes)
            Console.WriteLine(b);
        Console.WriteLine();
        Console.WriteLine($"当前目录：{root = Environment.CurrentDirectory}");
        Console.WriteLine();
        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (s, e) => {
            e.Cancel = true;
            cts.Cancel();
            Console.WriteLine("\n正在退出...");
        };
        var ct = cts.Token;
        var ct_task = Task.Delay(-1, ct);
        try {
            Console.Title = nameof(FileOnce);
            (new Thread(() => {
                long t0 = 0, t1 = 0, t2 = 0, t3 = 0;
                long a0 = 0, a1 = 0, a2 = 0, a3 = 0;
                while (!ct.WaitHandle.WaitOne(499)) {
                    var t = Interlocked.Read(ref start_time);
                    var a = Interlocked.Read(ref data_amount);
                    if (t <= 0) {
                        t1 = t2 = t3 = a1 = a2 = a3 = 0;
                        continue;
                    }
                    t0 = t1; a0 = a1;
                    t1 = t2; a1 = a2;
                    t2 = t3; a2 = a3;
                    t3 = t; a3 = a;
                    Console.Title = $"平均速度 = {StrSpeed(a3, t3)} ； 即时速度 = {StrSpeed(a3 - a0, t3 - t0)}";
                }
            })).Start();
        } catch (Exception ex) {
            Console.WriteLine(ex.Message);
            Console.WriteLine();
        }
        while (!ct.IsCancellationRequested) {
            try {
                await RunOneCycle(basePrefixes, ct, ct_task);
            } catch (OperationCanceledException) when (ct.IsCancellationRequested) {
                break;
            } catch (HttpListenerException ex) when (ex.Message.Contains("denied") || ex.Message.Contains("权限") || ex.ErrorCode == 5) {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("监听失败，请以管理员权限 (Windows) 或 root (Linux/macOS) 运行本程序。");
                Console.ResetColor();
                return;
            } catch (Exception ex) {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"意外错误`{ex.GetType()}`: {ex.Message}");
                Console.ResetColor();
                return;
            }
        }
    }
    static string StrBytes(decimal bytes) {
        if (bytes <= 1m) return $"{bytes} byte";
        if (bytes <= 1024m) return $"{bytes} bytes";
        if (bytes <= 1048576m) return $"{bytes / 1024m:F2} KiB";
        if (bytes <= 1073741824m) return $"{bytes / 1048576m:F2} MiB";
        return $"{bytes / 1073741824m:F2} GiB";
    }
    static string StrSpeed(long a, long t) {
        if (t < 1) return "??? ??";
        return $"{StrBytes(decimal.Divide(a, decimal.Divide(t, Stopwatch.Frequency)))}/s";
    }
    static async Task RunOneCycle(string[] basePrefixes, CancellationToken ct, Task ct_task) {
        string token = GenerateToken();
        Console.WriteLine($"\n--- Token: `{token}` ---");
        Console.WriteLine($"--- AesKeyNonce: `{Convert.ToHexString(aes_key_nonce_tag, 0, bytes_aes_key + bytes_aes_nonce)}` ---");
        using AesGcm aes = new(new ReadOnlySpan<byte>(aes_key_nonce_tag, 0, bytes_aes_key), bytes_aes_tag);
        var listener = new HttpListener();
        try {
            foreach (var bp in basePrefixes) {
                string full = bp + token + "/";
                listener.Prefixes.Add(full);
                //Console.WriteLine(full);
            }

            listener.Start();

            HttpListenerContext context;
            do {
                try {
                    var getContextTask = listener.GetContextAsync();
                    var completed = await Task.WhenAny(getContextTask, ct_task);
                    if (completed != getContextTask)
                        throw new OperationCanceledException(ct);
                    context = await getContextTask;
                } catch (ObjectDisposedException) when (ct.IsCancellationRequested) {
                    throw new OperationCanceledException(ct);
                }
            } while (await ProcessRequestAsync(aes, context, ct));
        } finally {
            Interlocked.Exchange(ref start_time, 0);
            Interlocked.Exchange(ref data_amount, 0);
            ct.WaitHandle.WaitOne(997);
            try { listener.Close(); } catch { }
            ct.WaitHandle.WaitOne(997);
        }
    }

    static async Task<bool> ProcessRequestAsync(AesGcm aes, HttpListenerContext context, CancellationToken ct) {
        wrote = false;
        var request = context.Request;
        var response = context.Response;
        try {
            response.AddHeader("Access-Control-Allow-Origin", "*");
            response.AddHeader("Access-Control-Allow-Methods", "GET, POST");
            response.AddHeader("Access-Control-Allow-Headers", "*");
            response.AddHeader("Access-Control-Allow-Private-Network", "true");
            response.AddHeader("Access-Control-Expose-Headers", "Blake3, Aes-Tag");
            response.AddHeader("Access-Control-Max-Age", "999");
            response.AddHeader("Cache-Control", "no-store, no-cache");
            response.AddHeader("Pragma", "no-cache");
            string method = request.HttpMethod.ToUpperInvariant();

            string[] segments;
            var url = request.Url;
            if (url is null || url.AbsolutePath.Length switch { <= 1 or > 1024 => true, _ => false } || (segments = url.Segments).Length < 2) {
                WriteTextResponse(response, 414, "url 长度非法");
                return false;
            }
            string rawName = segments[^1];

            string fileName;
            try {
                fileName = Uri.UnescapeDataString(rawName);
            } catch {
                WriteTextResponse(response, 400, "无效的文件名编码");
                return false;
            }

            // 文件名合法性检查
            if (string.IsNullOrWhiteSpace(fileName) ||
                fileName.IndexOfAny(InvalidFileNameChars) >= 0 ||
                IsReservedFileName(fileName)) {
                WriteTextResponse(response, 403, "文件名不合法");
                return false;
            }

            try {
                switch (method) {
                    case "GET":
                    await HandleGetAsync(aes, fileName, response, ct);
                    return false;
                    case "POST":
                    await HandlePostAsync(aes, fileName, request, response, ct);
                    return false;
                    case "OPTIONS":
                    WriteTextResponse(response, 200, "");
                    return true;
                    default:
                    WriteTextResponse(response, 405, "仅支持 GET 和 POST");
                    return false;
                }
            } catch (Exception ex) {
                WriteTextResponse(response, 400, ex.Message);
            }
        } catch (Exception ex) {
            Console.WriteLine($"{ex}");
            if (!wrote)
                WriteTextResponse(response, 500, ex.Message);
        }
        return false;
    }

    static async Task HandleGetAsync(AesGcm aes, string fileName, HttpListenerResponse response, CancellationToken ct) {
        string filePath = Path.Combine(root, fileName);
        if (!File.Exists(filePath)) {
            WriteTextResponse(response, 400, $"文件不存在: {fileName}");
            return;
        }

        var fileInfo = new FileInfo(filePath);
        if (fileInfo.Length > MaxFileSize) {
            WriteTextResponse(response, 400, $"文件过大，最大允许 {MaxFileSize} 字节");
            return;
        }

        int fileLength = (int)fileInfo.Length;
        using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read)) {
            await fs.ReadAsync(FileBuffer, 0, fileLength, ct);
        }

        Hash hash = Hasher.Hash(new ReadOnlySpan<byte>(FileBuffer, 0, fileLength));
        Span<byte> aes_data = new(aes_key_nonce_tag);
        var aes_tag = aes_data.Slice(bytes_aes_key + bytes_aes_nonce, bytes_aes_tag);
        aes.Encrypt(aes_data.Slice(bytes_aes_key, bytes_aes_nonce), new ReadOnlySpan<byte>(FileBuffer, 0, fileLength), new Span<byte>(AES_Buffer, 0, fileLength), aes_tag);

        response.StatusCode = 200;
        response.ContentType = "application/octet-stream";
        response.ContentLength64 = fileLength;
        response.AddHeader("Blake3", hash.ToString());
        response.AddHeader("Aes-Tag", Convert.ToHexString(aes_tag));

        await response.OutputStream.WriteAsync(AES_Buffer, 0, fileLength, ct);
        response.Close();

        Console.WriteLine($"[GET]\t{fileName}\tBlake3={hash}");
    }

    static async Task HandlePostAsync(AesGcm aes, string fileName, HttpListenerRequest request, HttpListenerResponse response, CancellationToken ct) {
        // 检查 Blake3 请求头
        string? blake3Header = request.Headers["Blake3"];
        if (string.IsNullOrWhiteSpace(blake3Header)) {
            WriteTextResponse(response, 400, "请求缺少 Blake3 头");
            return;
        }

        string? AesTag = request.Headers["Aes-Tag"];
        if (string.IsNullOrWhiteSpace(AesTag)) {
            WriteTextResponse(response, 400, "请求缺少 Aes-Tag 头");
            return;
        }

        new ReadOnlySpan<byte>(Convert.FromHexString(AesTag)).CopyTo(new Span<byte>(aes_key_nonce_tag, bytes_aes_key + bytes_aes_nonce, bytes_aes_tag));

        // Content-Length 预检
        if (request.ContentLength64 > MaxFileSize) {
            WriteTextResponse(response, 400, $"请求体过大，最大允许 {MaxFileSize} 字节");
            return;
        }
        long st = Stopwatch.GetTimestamp();
        Interlocked.Exchange(ref start_time, 0);
        Interlocked.Exchange(ref data_amount, 0);
        // 将请求体读入共享缓冲区
        var requestStream = request.InputStream;
        int totalRead = 0;
        int bytesRead;
        while ((bytesRead = await requestStream.ReadAsync(FileBuffer, totalRead, FileBuffer.Length - totalRead, ct)) > 0) {
            totalRead += bytesRead;
            if (totalRead > MaxFileSize) {
                WriteTextResponse(response, 400, $"请求体超出最大允许大小 {MaxFileSize} 字节");
                return;
            }
            Interlocked.Exchange(ref start_time, Stopwatch.GetTimestamp() - st);
            Interlocked.Exchange(ref data_amount, totalRead);
        }
        Interlocked.Exchange(ref start_time, Stopwatch.GetTimestamp() - st);
        Interlocked.Exchange(ref data_amount, totalRead);

        Span<byte> aes_data = new(aes_key_nonce_tag);
        var aes_tag = aes_data.Slice(bytes_aes_key + bytes_aes_nonce, bytes_aes_tag);
        aes.Decrypt(aes_data.Slice(bytes_aes_key, bytes_aes_nonce), new ReadOnlySpan<byte>(FileBuffer, 0, totalRead), aes_tag, new Span<byte>(AES_Buffer, 0, totalRead));

        // 计算实际哈希
        Hash actualHash = Hasher.Hash(new ReadOnlySpan<byte>(AES_Buffer, 0, totalRead));
        string actualHex = actualHash.ToString(); // 小写十六进制

        // 与请求头中的值进行不区分大小写的比较
        if (!string.Equals(actualHex, blake3Header, StringComparison.OrdinalIgnoreCase)) {
            WriteTextResponse(response, 400, $"Blake3 校验失败。期望: {blake3Header}, 实际: {actualHex}");
            return;
        }

        // 校验通过，写入磁盘
        string filePath = Path.Combine(root, fileName);
        using (var fs = new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.None)) {
            await fs.WriteAsync(AES_Buffer, 0, totalRead, ct);
        }

        WriteTextResponse(response, 200, "OK");

        Console.WriteLine($"[POST]\t{fileName}\tBlake3={blake3Header}");
    }

    static void WriteTextResponse(HttpListenerResponse response, int httpcode, string message) {
        if (wrote) return;
        if (httpcode != 200) Console.WriteLine($"{httpcode}\t{message}");
        response.StatusCode = httpcode;
        response.ContentType = "text/plain; charset=utf-8";
        wrote = true;
        response.Close(message?.Length >= 1 ? Encoding.UTF8.GetBytes(message) : Array.Empty<byte>(), true);
    }

    static string GenerateToken() {
        RandomNumberGenerator.Fill(aes_key_nonce_tag);
        var Tokens = TokenChars();
        var nToken = unchecked((uint)Tokens.Length);
        var pTokenIndexes = TokenIndexes.AsSpan();
        var ppTokenIndexes = MemoryMarshal.AsBytes(pTokenIndexes);
        RandomNumberGenerator.Fill(ppTokenIndexes);
        Span<char> temp = TokenLength <= 128 ? stackalloc char[TokenLength] : new char[TokenLength];
        for (int i = 0; i < TokenLength; ++i)
            temp[i] = Tokens[unchecked((int)(pTokenIndexes[i] % nToken))];
        return new string(temp);
    }
}
