using System.Buffers.Binary;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Options;
using SecureFileUploadPortal.Options;

namespace SecureFileUploadPortal.Validation;

/// <summary>
/// Streams the file to a clamd daemon using the INSTREAM protocol. Any failure to get a definite answer
/// (connection refused, timeout, size limit, unexpected reply) is reported as <see cref="ScanVerdict.Error"/>,
/// so the pipeline fails closed.
/// </summary>
public sealed class ClamAvSecurityScanner(IOptions<ValidationOptions> options, ILogger<ClamAvSecurityScanner> logger) : IFileSecurityScanner
{
    private const int ChunkSize = 64 * 1024;
    private readonly ClamAvOptions _options = options.Value.ClamAv;

    public string Name => "ClamAV";

    public async Task<ScanResult> ScanAsync(FileScanContext context, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(_options.TimeoutSeconds));
        try
        {
            await using var content = context.OpenRead();
            var reply = await InStreamAsync(content, timeout.Token);
            return Parse(reply);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return ScanResult.Error(Name, $"no answer from clamd within {_options.TimeoutSeconds}s");
        }
        catch (Exception ex) when (ex is SocketException or IOException)
        {
            logger.LogWarning(ex, "ClamAV at {Host}:{Port} is unavailable", _options.Host, _options.Port);
            return ScanResult.Error(Name, $"clamd unavailable ({ex.GetType().Name})");
        }
    }

    internal static ScanResult Parse(string reply)
    {
        const string engine = "ClamAV";
        reply = reply.TrimEnd('\0', '\n', ' ');
        if (reply.EndsWith(": OK", StringComparison.Ordinal))
            return ScanResult.Clean(engine, "no signature matched");
        if (reply.EndsWith(" FOUND", StringComparison.Ordinal))
        {
            var signature = reply[(reply.IndexOf(": ", StringComparison.Ordinal) + 2)..^" FOUND".Length];
            return ScanResult.Infected(engine, $"signature {signature}");
        }
        return ScanResult.Error(engine, $"unexpected clamd reply: {(reply.Length > 120 ? reply[..120] : reply)}");
    }

    private async Task<string> InStreamAsync(Stream content, CancellationToken ct)
    {
        using var client = new TcpClient();
        await client.ConnectAsync(_options.Host, _options.Port, ct);
        await using var network = client.GetStream();

        await network.WriteAsync("zINSTREAM\0"u8.ToArray(), ct);
        var length = new byte[4];
        var buffer = new byte[ChunkSize];
        int read;
        while ((read = await content.ReadAsync(buffer, ct)) > 0)
        {
            BinaryPrimitives.WriteUInt32BigEndian(length, (uint)read);
            await network.WriteAsync(length, ct);
            await network.WriteAsync(buffer.AsMemory(0, read), ct);
        }
        BinaryPrimitives.WriteUInt32BigEndian(length, 0);
        await network.WriteAsync(length, ct);

        using var reply = new MemoryStream();
        var chunk = new byte[256];
        while ((read = await network.ReadAsync(chunk, ct)) > 0)
        {
            reply.Write(chunk, 0, read);
            if (chunk[read - 1] == 0) break;
        }
        return Encoding.ASCII.GetString(reply.ToArray());
    }
}
