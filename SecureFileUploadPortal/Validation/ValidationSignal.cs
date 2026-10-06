using System.Threading.Channels;

namespace SecureFileUploadPortal.Validation;

/// <summary>Wakes the validation worker as soon as an upload is stored instead of waiting for the next poll.</summary>
public sealed class ValidationSignal
{
    private readonly Channel<bool> _channel = Channel.CreateBounded<bool>(new BoundedChannelOptions(1) { FullMode = BoundedChannelFullMode.DropWrite });

    public void Notify() => _channel.Writer.TryWrite(true);

    public async Task WaitAsync(TimeSpan timeout, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        try
        {
            if (await _channel.Reader.WaitToReadAsync(cts.Token)) _channel.Reader.TryRead(out _);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
        }
    }
}
