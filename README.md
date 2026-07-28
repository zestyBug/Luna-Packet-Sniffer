# Luna-Packet-Sniffer

LunaPacketSniffer is a Windows packet-capture and analysis tool with per-process filtering. It captures and indexes IPv4 and IPv6 traffic, including TCP, UDP, ICMP, DNS, HTTP/HTTPS, WebSocket, and KCP.

Captured data is written to PCAPNG, SQLite, and HAR files for later inspection.

## Running

Run the application as Administrator:

```text
LunaPacketSniffer.App\bin\Debug\net10.0-windows\LunaPacketSniffer.App.exe
```

Select a filter type at the top of the window, enter or select its value, and click **Add filter**. Multiple filters of the same type are combined with OR; filters of different types are combined with AND.

- **PID**: Select a running process from the drop-down list. The list refreshes each time it is opened.
- **Process Name**: Matches every running process with the specified executable name.
- **EXE Path**: Matches the full path of an executable.
- **Protocol**: Select TCP, UDP, or HTTP(S). HTTP(S) matches the standard ports 80 and 443.

HTTPS decryption is enabled while a capture is running. The application temporarily changes the current user's Windows HTTPS proxy setting to its local proxy and restores the exact previous setting when capture stops, the application exits normally, or capture startup fails.

The generated root CA remains installed until **Remove Root CA** is selected in the application.

## Output

Each capture is written to:

```text
<application directory>\out\<capture-id>\
```

The capture directory contains:

- `capture.pcapng` — Raw packets as captured, including encrypted TLS packets.
- `capture.index.sqlite` — An index of packets, flows, processes, HTTP transactions, WebSocket messages, and KCP conversations.
- `capture.http.har` — Decrypted HTTP(S) headers and eligible text bodies in HAR format.
- `sessions.json` — TCP and UDP conversation summaries.
- `bodies\` — Individual HTTP request/response bodies and WebSocket message bodies.

`LunaPacketSniffer.log` is stored beside the executable and is cleared on every application startup.

The user interface provides dedicated tabs for decrypted HTTP(S), WebSocket messages, TCP/UDP flows, and KCP conversations. HTTP bodies are decoded for gzip, deflate, and Brotli when possible; JSON bodies are formatted for readability.

TCP flow details include separate inbound and outbound stream previews, retransmission counts, out-of-order segment counts, and the current number of missing bytes.

## Build and Test

Build the native DLL first, then build and test the .NET solution:

```powershell
cmake --preset windows-x64
cmake --build --preset windows-x64-debug
dotnet build LunaPacketSniffer.sln --configuration Debug
dotnet test LunaPacketSniffer.sln --configuration Debug
```
