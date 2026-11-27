namespace GorevYoneticisi.Core.Metrics;

/// <summary>Turkish names for MIB_TCP_STATE values.</summary>
public static class TcpStates
{
    public static string ToTurkish(int state) => state switch
    {
        1 => "Kapalı",
        2 => "Dinliyor",
        3 or 4 => "Bağlanıyor",
        5 => "Bağlı",
        6 or 7 or 8 or 9 or 10 => "Kapanıyor",
        11 => "Kapandı (bekleme)",
        12 => "Siliniyor",
        _ => "Bilinmiyor",
    };
}
