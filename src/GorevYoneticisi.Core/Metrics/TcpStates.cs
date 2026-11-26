namespace GorevYoneticisi.Core.Metrics;

/// <summary>Turkish names for MIB_TCP_STATE values.</summary>
public static class TcpStates
{
    public static string ToTurkish(int state) => state switch
    {
        1 => "Kapalı",
        2 => "Dinliyor",
        3 => "Bağlanıyor (SYN gönderildi)",
        4 => "Bağlanıyor (SYN alındı)",
        5 => "Bağlı",
        6 => "Kapanıyor (FIN_WAIT1)",
        7 => "Kapanıyor (FIN_WAIT2)",
        8 => "Kapanma bekleniyor",
        9 => "Kapanıyor",
        10 => "Son onay bekleniyor",
        11 => "Bekleme (TIME_WAIT)",
        12 => "Siliniyor",
        _ => "Bilinmiyor",
    };
}
