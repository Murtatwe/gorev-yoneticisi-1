using System.Net;
using System.Runtime.InteropServices;
using GorevYoneticisi.App.Native;
using GorevYoneticisi.Core.Metrics;

namespace GorevYoneticisi.App.Services;

public sealed record ConnectionInfo(
    string Protocol,
    string LocalAddress,
    int LocalPort,
    string RemoteAddress,
    int RemotePort,
    int StateCode,
    int Pid)
{
    public string State => Protocol.StartsWith("UDP", StringComparison.Ordinal) ? "—" : TcpStates.ToTurkish(StateCode);
    public string Local => FormatEndpoint(LocalAddress, LocalPort);
    public string Remote => Protocol.StartsWith("UDP", StringComparison.Ordinal) || RemotePort == 0 && IsUnspecified(RemoteAddress)
        ? "—" : FormatEndpoint(RemoteAddress, RemotePort);

    private static bool IsUnspecified(string a) => a is "0.0.0.0" or "::";
    private static string FormatEndpoint(string a, int port) => a.Contains(':') ? $"[{a}]:{port}" : $"{a}:{port}";
}

/// <summary>TCP and UDP endpoints (IPv4 + IPv6) with the owning process, via IP Helper.</summary>
internal static class NetworkConnections
{
    public static List<ConnectionInfo> Read()
    {
        var list = new List<ConnectionInfo>();
        ReadTable(list, tcp: true, IpHlpApi.AF_INET);
        ReadTable(list, tcp: true, IpHlpApi.AF_INET6);
        ReadTable(list, tcp: false, IpHlpApi.AF_INET);
        ReadTable(list, tcp: false, IpHlpApi.AF_INET6);
        return list;
    }

    private static unsafe void ReadTable(List<ConnectionInfo> list, bool tcp, int af)
    {
        int size = 0;
        uint status = tcp
            ? IpHlpApi.GetExtendedTcpTable(IntPtr.Zero, ref size, false, af, IpHlpApi.TCP_TABLE_OWNER_PID_ALL, 0)
            : IpHlpApi.GetExtendedUdpTable(IntPtr.Zero, ref size, false, af, IpHlpApi.UDP_TABLE_OWNER_PID, 0);

        for (int attempt = 0; attempt < 4 && status == IpHlpApi.ERROR_INSUFFICIENT_BUFFER; attempt++)
        {
            size += 4096; // the table can grow between the two calls
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                status = tcp
                    ? IpHlpApi.GetExtendedTcpTable(buffer, ref size, false, af, IpHlpApi.TCP_TABLE_OWNER_PID_ALL, 0)
                    : IpHlpApi.GetExtendedUdpTable(buffer, ref size, false, af, IpHlpApi.UDP_TABLE_OWNER_PID, 0);
                if (status != IpHlpApi.NO_ERROR) continue;

                int count = *(int*)buffer;
                byte* rows = (byte*)buffer + 4;
                for (int i = 0; i < count; i++)
                {
                    if (tcp && af == IpHlpApi.AF_INET)
                    {
                        var r = ((IpHlpApi.MIB_TCPROW_OWNER_PID*)rows)[i];
                        list.Add(new ConnectionInfo("TCP", new IPAddress(r.LocalAddr).ToString(), IpHlpApi.Port(r.LocalPort),
                            new IPAddress(r.RemoteAddr).ToString(), IpHlpApi.Port(r.RemotePort), (int)r.State, (int)r.OwningPid));
                    }
                    else if (tcp)
                    {
                        var r = ((IpHlpApi.MIB_TCP6ROW_OWNER_PID*)rows)[i];
                        list.Add(new ConnectionInfo("TCPv6", V6(r.LocalAddr, r.LocalScopeId), IpHlpApi.Port(r.LocalPort),
                            V6(r.RemoteAddr, r.RemoteScopeId), IpHlpApi.Port(r.RemotePort), (int)r.State, (int)r.OwningPid));
                    }
                    else if (af == IpHlpApi.AF_INET)
                    {
                        var r = ((IpHlpApi.MIB_UDPROW_OWNER_PID*)rows)[i];
                        list.Add(new ConnectionInfo("UDP", new IPAddress(r.LocalAddr).ToString(), IpHlpApi.Port(r.LocalPort), "", 0, 0, (int)r.OwningPid));
                    }
                    else
                    {
                        var r = ((IpHlpApi.MIB_UDP6ROW_OWNER_PID*)rows)[i];
                        list.Add(new ConnectionInfo("UDPv6", V6(r.LocalAddr, r.LocalScopeId), IpHlpApi.Port(r.LocalPort), "", 0, 0, (int)r.OwningPid));
                    }
                }
                return;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
    }

    private static unsafe string V6(byte* address, uint scope)
    {
        var bytes = new byte[16];
        for (int i = 0; i < 16; i++) bytes[i] = address[i];
        return new IPAddress(bytes, scope).ToString();
    }
}
