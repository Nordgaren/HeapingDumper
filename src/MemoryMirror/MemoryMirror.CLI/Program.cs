using System.Diagnostics;
using MemoryMirror.Shared;

// TODO: allow selection by process ID as well
var process = Process.GetProcessesByName("eldenring").Single();

// Pause all threads so we no mutations happen to the process memory as we're dumping it
process.Suspend();
Console.WriteLine("Pausing process...");

var memorySegments = process.EnumerateMemorySegments();
var snapshot = process.CreateSnapshot();
var modules = SnapshotModuleHelper.EnumerateModules(snapshot);

var chunks = new Dictionary<IntPtr, DumpableChunk>();
foreach (var segment in memorySegments.OrderBy(m => m.Address)) {
    // Mach anything that is between the start and the end of the module
    var associatedModule = modules.FirstOrDefault(
        m =>
            (Int64) m.Address <= (Int64) segment.Address &&
            (Int64) m.Address + (Int64) m.Size >= (Int64) segment.Address
    );
    
    var chunkAddress = associatedModule?.Address ?? segment.Address;
    var chunkSize = associatedModule?.Size ?? segment.Size;
    if (chunks.ContainsKey(chunkAddress)) {
        chunks[chunkAddress].Segments.Add(segment);
    } else {
        var chunk = new DumpableChunk(
            associatedModule?.Name,
            chunkSize,
            new List<ProcessUtilities.ProcessMemorySegment> { segment }
        );
        chunks[chunkAddress] = chunk;
    }
}

var readHandle = process.GetReadHandle();
foreach (var chunk in chunks) {
    var baseAddress = chunk.Key;
    var segments = chunk.Value.Segments;
    
    string path = $"./{chunk.Key:X}-{chunk.Value.Name ?? "UNKNOWN"}.dmp";
    var fileStream = File.OpenWrite(path);
    
    foreach (var segment in segments) {
        var segmentOffset = (UInt64) segment.Address - (UInt64) baseAddress;
        var takenSize = (UInt64) 0x0;

        while (takenSize < (UInt64) segment.Size) {
            // Chunk by max 1GB
            var currentChunkedSize = (UInt64) segment.Size > 0x3B9ACA00 ? 0x3B9ACA00 : (UInt64) segment.Size;
            var chunkedSegmentBuffer = ProcessUtilities.ReadMemoryToBuffer(
                readHandle, 
                (IntPtr)((UInt64) segment.Address + takenSize),
                (IntPtr) currentChunkedSize
            );
            
            fileStream.Seek(0, SeekOrigin.Begin);
            fileStream.Seek((long) (segmentOffset + takenSize), SeekOrigin.Begin);
            fileStream.Write(chunkedSegmentBuffer);

            takenSize += currentChunkedSize;
        }
    }
    
    Console.WriteLine($"Written dump to {path} ({chunk.Value.Size})");
}

Console.WriteLine("Resuming process...");
process.Resume();

public record DumpableChunk(string? Name, IntPtr Size, List<ProcessUtilities.ProcessMemorySegment> Segments);