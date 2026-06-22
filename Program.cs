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
    static readonly char[] InvalidFileNameChars = Path.GetInvalidFileNameChars();
    static volatile bool wrote = false;

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
        if (args.Length == 0) {
            Console.WriteLine("用法: FileOnce <http前缀1> [http前缀2] ...");
            Console.WriteLine("示例: FileOnce http://127.0.0.1:6543/fileonce/ http://8.9.10.11:80/outside/");
            return;
        }

        var basePrefixes = args.Select(p => p.EndsWith("/") ? p : p + "/").ToArray();
        foreach (var b in basePrefixes)
            Console.WriteLine(b);
        Console.WriteLine();
        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (s, e) => {
            e.Cancel = true;
            cts.Cancel();
            Console.WriteLine("\n正在退出...");
        };
        var ct = cts.Token;
        var ct_task = Task.Delay(-1, ct);
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
                Console.WriteLine($"意外错误: {ex.Message}");
                Console.ResetColor();
                return;
            }
        }
    }

    static async Task RunOneCycle(string[] basePrefixes, CancellationToken ct, Task ct_task) {
        string token = GenerateToken();
        Console.WriteLine($"\n--- 新令牌: `{token}` ---");

        var listener = new HttpListener();
        try {
            foreach (var bp in basePrefixes) {
                string full = bp + token + "/";
                listener.Prefixes.Add(full);
                Console.WriteLine(full);
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
            } while (await ProcessRequestAsync(context, ct));
        } finally {
            ct_task.Wait(997);
            try { listener.Close(); } catch { }
        }
    }

    static async Task<bool> ProcessRequestAsync(HttpListenerContext context, CancellationToken ct) {
        wrote = false;
        var request = context.Request;
        var response = context.Response;
        try {
            response.AddHeader("Access-Control-Allow-Origin", "*");
            response.AddHeader("Access-Control-Allow-Methods", "GET, POST");
            response.AddHeader("Access-Control-Allow-Headers", "*");
            response.AddHeader("Access-Control-Allow-Private-Network", "true");
            response.AddHeader("Access-Control-Expose-Headers", "Blake3");
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
                    await HandleGetAsync(fileName, response, ct);
                    return false;
                    case "POST":
                    await HandlePostAsync(fileName, request, response, ct);
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

    static async Task HandleGetAsync(string fileName, HttpListenerResponse response, CancellationToken ct) {
        string filePath = Path.Combine(Environment.CurrentDirectory, fileName);
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

        Hash hash = Hasher.Hash(FileBuffer.AsSpan(0, fileLength));

        response.StatusCode = 200;
        response.ContentType = "application/octet-stream";
        response.ContentLength64 = fileLength;
        response.Headers.Add("Blake3", hash.ToString());

        await response.OutputStream.WriteAsync(FileBuffer, 0, fileLength, ct);
        response.Close();

        Console.WriteLine($"[GET] {fileName} Blake3={hash}");
    }

    static async Task HandlePostAsync(string fileName, HttpListenerRequest request, HttpListenerResponse response, CancellationToken ct) {
        // 检查 Blake3 请求头
        string? blake3Header = request.Headers["Blake3"];
        if (string.IsNullOrWhiteSpace(blake3Header)) {
            WriteTextResponse(response, 400, "请求缺少 Blake3 头");
            return;
        }

        // Content-Length 预检
        if (request.ContentLength64 > MaxFileSize) {
            WriteTextResponse(response, 400, $"请求体过大，最大允许 {MaxFileSize} 字节");
            return;
        }

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
        }

        // 计算实际哈希
        Hash actualHash = Hasher.Hash(FileBuffer.AsSpan(0, totalRead));
        string actualHex = actualHash.ToString(); // 小写十六进制

        // 与请求头中的值进行不区分大小写的比较
        if (!string.Equals(actualHex, blake3Header, StringComparison.OrdinalIgnoreCase)) {
            WriteTextResponse(response, 400, $"Blake3 校验失败。期望: {blake3Header}, 实际: {actualHex}");
            return;
        }

        // 校验通过，写入磁盘
        string filePath = Path.Combine(Environment.CurrentDirectory, fileName);
        using (var fs = new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.None)) {
            await fs.WriteAsync(FileBuffer, 0, totalRead, ct);
        }

        WriteTextResponse(response, 200, "OK");

        Console.WriteLine($"[POST] {fileName} Blake3={blake3Header}");
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
