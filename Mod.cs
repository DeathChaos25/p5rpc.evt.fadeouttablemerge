using p5rpc.evt.fadeouttablemerge.Configuration;
using p5rpc.evt.fadeouttablemerge.Template;
using Reloaded.Hooks.Definitions;
using Reloaded.Hooks.ReloadedII.Interfaces;
using Reloaded.Mod.Interfaces;
using Reloaded.Mod.Interfaces.Internal;
using System.Runtime.InteropServices;
using IReloadedHooks = Reloaded.Hooks.ReloadedII.Interfaces.IReloadedHooks;
using static p5rpc.evt.fadeouttablemerge.Utils;

namespace p5rpc.evt.fadeouttablemerge
{
    /// <summary>
    /// Your mod logic goes here.
    /// </summary>
    public class Mod : ModBase // <= Do not Remove.
    {
        /// <summary>
        /// Provides access to the mod loader API.
        /// </summary>
        private readonly IModLoader _modLoader;

        /// <summary>
        /// Provides access to the Reloaded.Hooks API.
        /// </summary>
        /// <remarks>This is null if you remove dependency on Reloaded.SharedLib.Hooks in your mod.</remarks>
        private readonly IReloadedHooks? _hooks;

        /// <summary>
        /// Provides access to the Reloaded logger.
        /// </summary>
        private readonly ILogger _logger;

        /// <summary>
        /// Entry point into the mod, instance that created this class.
        /// </summary>
        private readonly IMod _owner;

        /// <summary>
        /// Provides access to this mod's configuration.
        /// </summary>
        private Config _configuration;

        /// <summary>
        /// The configuration of the currently executing mod.
        /// </summary>
        private readonly IModConfig _modConfig;

        private delegate nint GetEvtFadeoutID_Delegate(nint a1);
        private IHook<GetEvtFadeoutID_Delegate> _getEvtFadeoutID;

        private static nint EvtFadeoutTablePointerAddr;

        private static bool hasCreatedTable = false;

        public static byte[] tableBytes = new byte[3000 * 8];
        GCHandle tableHandle = GCHandle.Alloc(tableBytes, GCHandleType.Pinned);

        public static nint TableAddress = 0;

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct EvtFadeoutEntry
        {
            public ushort major_id;
            public ushort minor_id;
            public ushort fade_id;
            public ushort align;

            public override string ToString()
            {
                return $"new EvtFadeoutEntry {{ major_id = {major_id}, minor_id = {minor_id}, fade_id = {fade_id} }}";
            }
        }

        public static List<EvtFadeoutEntry> EvtFadeoutTable { get; } = new List<EvtFadeoutEntry>();

        public Mod(ModContext context)
        {
            _modLoader = context.ModLoader;
            _hooks = context.Hooks;
            _logger = context.Logger;
            _owner = context.Owner;
            _configuration = context.Configuration;
            _modConfig = context.ModConfig;

            Initialise(_logger, _configuration, _modLoader);

            AddOriginalEntries();

            SigScan("48 89 5C 24 ?? 48 89 6C 24 ?? 56 57 41 56 48 83 EC 20 48 8B 41 ?? 48 8B F9", "GetEvtFadeoutID", address =>
            {
                _getEvtFadeoutID = _hooks.CreateHook<GetEvtFadeoutID_Delegate>(GetEvtFadeoutID, address).Activate();
            });

            SigScan("48 8B 0D ?? ?? ?? ?? 33 F6 48 85 C9 74 ?? E8 ?? ?? ?? ?? 48 89 35 ?? ?? ?? ?? 40 38 35 ?? ?? ?? ??", "FadeoutTable Pointer Access", address =>
            {
                EvtFadeoutTablePointerAddr = (nint)GetGlobalAddress(address + 3);
            });

            _modLoader.ModLoading += ModLoading;
        }

        private void ModLoading(IModV1 mod, IModConfigV1 modConfig)
        {
            var modsPath = Path.Combine(_modLoader.GetDirectoryForModId(modConfig.ModId), "evt");
            if (!Directory.Exists(modsPath))
                return;

            AddFolder(modsPath);
        }

        private void AddFolder(string folder)
        {
            var fadeoutFile = Path.Join(folder, "evtFadeoutData.txt");
            if (File.Exists(fadeoutFile))
            {
                Log($"Loading Fadeout Data from {fadeoutFile}");

                var fadeoutEntries = DeserializeFadeoutFile(fadeoutFile);
                foreach (var entry in fadeoutEntries)
                {
                    LogDebug("Adding entry: " + entry.ToString());
                    EvtFadeoutTable.Add(entry);
                }
            }
        }

        internal static List<EvtFadeoutEntry> DeserializeFadeoutFile(string filePath)
        {
            var lines = File.ReadAllLines(filePath);
            var result = new List<EvtFadeoutEntry>();

            foreach (var line in lines)
            {
                if (line.StartsWith("//") || string.IsNullOrWhiteSpace(line))
                    continue;

                var parts = line.Split("|", StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length != 3)
                    continue;

                try
                {
                    ushort major = ushort.Parse(parts[0]);
                    ushort minor = ushort.Parse(parts[1]);
                    ushort fade = ushort.Parse(parts[2]);

                    var existingIndex = result.FindIndex(e => e.major_id == major && e.minor_id == minor);
                    if (existingIndex >= 0)
                    {
                        var existing = result[existingIndex];
                        existing.fade_id = fade;
                        result[existingIndex] = existing;
                        Log($"Updated existing entry: {major}|{minor} (new fade: {fade})");
                    }
                    else
                    {
                        Log($"Adding new entry: e{major:d3}_{minor:d3} (fade: {fade})");

                        result.Add(new EvtFadeoutEntry
                        {
                            major_id = major,
                            minor_id = minor,
                            fade_id = fade,
                            align = 0
                        });
                    }
                }
                catch (FormatException ex)
                {
                    Log($"Skipping invalid line: {line} - {ex.Message}");
                }
            }

            return result;
        }

        public nint GetEvtFadeoutID(nint a1)
        {
            if (!hasCreatedTable)
            {
                hasCreatedTable = true;

                TableAddress = tableHandle.AddrOfPinnedObject();

                for (int i = 0; i < EvtFadeoutTable.Count; i++)
                {
                    byte[] entryBytes = GetBytes(EvtFadeoutTable[i]);
                    Marshal.Copy(entryBytes, 0, TableAddress + (i * 8), 8);
                }

                Log($"Wrote new table located at 0x{TableAddress:X8} to pointer address located at 0x{EvtFadeoutTablePointerAddr:X8}");
            }
            Marshal.WriteIntPtr(EvtFadeoutTablePointerAddr, TableAddress);
            Marshal.WriteIntPtr(EvtFadeoutTablePointerAddr + 8, 3000);

            nint result = _getEvtFadeoutID.OriginalFunction(a1);

            return result;
        }

        public static byte[] GetBytes<T>(T str) where T : struct
        {
            int size = Marshal.SizeOf(str);
            byte[] arr = new byte[size];
            IntPtr ptr = Marshal.AllocHGlobal(size);

            Marshal.StructureToPtr(str, ptr, true);
            Marshal.Copy(ptr, arr, 0, size);
            Marshal.FreeHGlobal(ptr);

            return arr;
        }

        private void AddOriginalEntries()
        {
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 80, minor_id = 1, fade_id = 1, align = 0 }); // Entry 0
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 80, minor_id = 2, fade_id = 1, align = 0 }); // Entry 1
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 80, minor_id = 3, fade_id = 1, align = 0 }); // Entry 2
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 80, minor_id = 40, fade_id = 1, align = 0 }); // Entry 3
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 80, minor_id = 50, fade_id = 1, align = 0 }); // Entry 4
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 99, minor_id = 0, fade_id = 23, align = 0 }); // Entry 5
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 99, minor_id = 10, fade_id = 16, align = 0 }); // Entry 6
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 99, minor_id = 20, fade_id = 16, align = 0 }); // Entry 7
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 99, minor_id = 30, fade_id = 8, align = 0 }); // Entry 8
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 99, minor_id = 40, fade_id = 16, align = 0 }); // Entry 9
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 99, minor_id = 50, fade_id = 16, align = 0 }); // Entry 10
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 99, minor_id = 60, fade_id = 16, align = 0 }); // Entry 11
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 99, minor_id = 70, fade_id = 16, align = 0 }); // Entry 12
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 100, minor_id = 3, fade_id = 16, align = 0 }); // Entry 13
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 100, minor_id = 4, fade_id = 16, align = 0 }); // Entry 14
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 101, minor_id = 1, fade_id = 1, align = 0 }); // Entry 15
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 102, minor_id = 1, fade_id = 16, align = 0 }); // Entry 16
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 103, minor_id = 1, fade_id = 1, align = 0 }); // Entry 17
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 103, minor_id = 2, fade_id = 1, align = 0 }); // Entry 18
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 104, minor_id = 1, fade_id = 1, align = 0 }); // Entry 19
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 105, minor_id = 1, fade_id = 16, align = 0 }); // Entry 20
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 105, minor_id = 301, fade_id = 16, align = 0 }); // Entry 21
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 106, minor_id = 1, fade_id = 16, align = 0 }); // Entry 22
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 106, minor_id = 2, fade_id = 1, align = 0 }); // Entry 23
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 107, minor_id = 1, fade_id = 1, align = 0 }); // Entry 24
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 107, minor_id = 2, fade_id = 16, align = 0 }); // Entry 25
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 108, minor_id = 1, fade_id = 16, align = 0 }); // Entry 26
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 108, minor_id = 2, fade_id = 16, align = 0 }); // Entry 27
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 108, minor_id = 3, fade_id = 16, align = 0 }); // Entry 28
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 108, minor_id = 101, fade_id = 16, align = 0 }); // Entry 29
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 109, minor_id = 1, fade_id = 16, align = 0 }); // Entry 30
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 109, minor_id = 2, fade_id = 1, align = 0 }); // Entry 31
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 109, minor_id = 3, fade_id = 1, align = 0 }); // Entry 32
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 109, minor_id = 4, fade_id = 16, align = 0 }); // Entry 33
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 109, minor_id = 205, fade_id = 16, align = 0 }); // Entry 34
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 110, minor_id = 1, fade_id = 21, align = 0 }); // Entry 35
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 111, minor_id = 1, fade_id = 1, align = 0 }); // Entry 36
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 112, minor_id = 1, fade_id = 16, align = 0 }); // Entry 37
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 113, minor_id = 1, fade_id = 1, align = 0 }); // Entry 38
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 113, minor_id = 2, fade_id = 1, align = 0 }); // Entry 39
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 115, minor_id = 1, fade_id = 16, align = 0 }); // Entry 40
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 116, minor_id = 1, fade_id = 16, align = 0 }); // Entry 41
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 116, minor_id = 301, fade_id = 16, align = 0 }); // Entry 42
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 116, minor_id = 401, fade_id = 16, align = 0 }); // Entry 43
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 118, minor_id = 1, fade_id = 23, align = 0 }); // Entry 44
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 119, minor_id = 1, fade_id = 16, align = 0 }); // Entry 45
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 120, minor_id = 1, fade_id = 21, align = 0 }); // Entry 46
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 120, minor_id = 2, fade_id = 16, align = 0 }); // Entry 47
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 121, minor_id = 1, fade_id = 2, align = 0 }); // Entry 48
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 121, minor_id = 2, fade_id = 2, align = 0 }); // Entry 49
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 122, minor_id = 1, fade_id = 2, align = 0 }); // Entry 50
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 123, minor_id = 1, fade_id = 16, align = 0 }); // Entry 51
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 124, minor_id = 1, fade_id = 16, align = 0 }); // Entry 52
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 124, minor_id = 101, fade_id = 16, align = 0 }); // Entry 53
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 126, minor_id = 101, fade_id = 16, align = 0 }); // Entry 54
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 127, minor_id = 1, fade_id = 1, align = 0 }); // Entry 55
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 127, minor_id = 201, fade_id = 2, align = 0 }); // Entry 56
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 127, minor_id = 301, fade_id = 2, align = 0 }); // Entry 57
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 128, minor_id = 1, fade_id = 2, align = 0 }); // Entry 58
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 128, minor_id = 2, fade_id = 1, align = 0 }); // Entry 59
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 128, minor_id = 3, fade_id = 23, align = 0 }); // Entry 60
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 129, minor_id = 1, fade_id = 16, align = 0 }); // Entry 61
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 129, minor_id = 2, fade_id = 16, align = 0 }); // Entry 62
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 130, minor_id = 1, fade_id = 16, align = 0 }); // Entry 63
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 132, minor_id = 2, fade_id = 1, align = 0 }); // Entry 64
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 133, minor_id = 1, fade_id = 16, align = 0 }); // Entry 65
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 134, minor_id = 1, fade_id = 23, align = 0 }); // Entry 66
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 135, minor_id = 1, fade_id = 2, align = 0 }); // Entry 67
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 135, minor_id = 2, fade_id = 16, align = 0 }); // Entry 68
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 136, minor_id = 1, fade_id = 16, align = 0 }); // Entry 69
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 136, minor_id = 101, fade_id = 16, align = 0 }); // Entry 70
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 137, minor_id = 2, fade_id = 1, align = 0 }); // Entry 71
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 138, minor_id = 1, fade_id = 16, align = 0 }); // Entry 72
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 140, minor_id = 1, fade_id = 8, align = 0 }); // Entry 73
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 141, minor_id = 1, fade_id = 16, align = 0 }); // Entry 74
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 141, minor_id = 101, fade_id = 16, align = 0 }); // Entry 75
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 142, minor_id = 1, fade_id = 2, align = 0 }); // Entry 76
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 143, minor_id = 1, fade_id = 2, align = 0 }); // Entry 77
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 144, minor_id = 1, fade_id = 16, align = 0 }); // Entry 78
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 145, minor_id = 1, fade_id = 1, align = 0 }); // Entry 79
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 145, minor_id = 2, fade_id = 16, align = 0 }); // Entry 80
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 145, minor_id = 3, fade_id = 2, align = 0 }); // Entry 81
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 146, minor_id = 1, fade_id = 16, align = 0 }); // Entry 82
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 146, minor_id = 101, fade_id = 16, align = 0 }); // Entry 83
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 147, minor_id = 1, fade_id = 16, align = 0 }); // Entry 84
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 148, minor_id = 1, fade_id = 2, align = 0 }); // Entry 85
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 150, minor_id = 1, fade_id = 16, align = 0 }); // Entry 86
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 151, minor_id = 1, fade_id = 16, align = 0 }); // Entry 87
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 152, minor_id = 1, fade_id = 2, align = 0 }); // Entry 88
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 152, minor_id = 301, fade_id = 16, align = 0 }); // Entry 89
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 153, minor_id = 1, fade_id = 1, align = 0 }); // Entry 90
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 156, minor_id = 1, fade_id = 16, align = 0 }); // Entry 91
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 157, minor_id = 1, fade_id = 16, align = 0 }); // Entry 92
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 157, minor_id = 2, fade_id = 16, align = 0 }); // Entry 93
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 158, minor_id = 1, fade_id = 23, align = 0 }); // Entry 94
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 159, minor_id = 1, fade_id = 8, align = 0 }); // Entry 95
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 159, minor_id = 101, fade_id = 16, align = 0 }); // Entry 96
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 160, minor_id = 2, fade_id = 1, align = 0 }); // Entry 97
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 160, minor_id = 3, fade_id = 23, align = 0 }); // Entry 98
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 160, minor_id = 4, fade_id = 16, align = 0 }); // Entry 99
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 160, minor_id = 12, fade_id = 1, align = 0 }); // Entry 100
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 160, minor_id = 13, fade_id = 1, align = 0 }); // Entry 101
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 160, minor_id = 601, fade_id = 16, align = 0 }); // Entry 102
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 166, minor_id = 1, fade_id = 16, align = 0 }); // Entry 103
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 167, minor_id = 1, fade_id = 16, align = 0 }); // Entry 104
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 167, minor_id = 11, fade_id = 16, align = 0 }); // Entry 105
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 168, minor_id = 1, fade_id = 23, align = 0 }); // Entry 106
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 168, minor_id = 11, fade_id = 23, align = 0 }); // Entry 107
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 169, minor_id = 1, fade_id = 21, align = 0 }); // Entry 108
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 170, minor_id = 1, fade_id = 1, align = 0 }); // Entry 109
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 172, minor_id = 1, fade_id = 16, align = 0 }); // Entry 110
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 174, minor_id = 1, fade_id = 1, align = 0 }); // Entry 111
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 174, minor_id = 2, fade_id = 16, align = 0 }); // Entry 112
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 175, minor_id = 1, fade_id = 16, align = 0 }); // Entry 113
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 176, minor_id = 1, fade_id = 16, align = 0 }); // Entry 114
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 177, minor_id = 1, fade_id = 16, align = 0 }); // Entry 115
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 178, minor_id = 1, fade_id = 16, align = 0 }); // Entry 116
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 179, minor_id = 2, fade_id = 16, align = 0 }); // Entry 117
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 179, minor_id = 3, fade_id = 16, align = 0 }); // Entry 118
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 179, minor_id = 201, fade_id = 16, align = 0 }); // Entry 119
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 179, minor_id = 301, fade_id = 16, align = 0 }); // Entry 120
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 179, minor_id = 401, fade_id = 1, align = 0 }); // Entry 121
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 180, minor_id = 1, fade_id = 16, align = 0 }); // Entry 122
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 181, minor_id = 102, fade_id = 16, align = 0 }); // Entry 123
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 181, minor_id = 103, fade_id = 16, align = 0 }); // Entry 124
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 182, minor_id = 1, fade_id = 16, align = 0 }); // Entry 125
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 183, minor_id = 1, fade_id = 21, align = 0 }); // Entry 126
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 183, minor_id = 2, fade_id = 1, align = 0 }); // Entry 127
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 184, minor_id = 1, fade_id = 16, align = 0 }); // Entry 128
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 185, minor_id = 1, fade_id = 16, align = 0 }); // Entry 129
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 185, minor_id = 2, fade_id = 16, align = 0 }); // Entry 130
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 185, minor_id = 101, fade_id = 16, align = 0 }); // Entry 131
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 185, minor_id = 201, fade_id = 16, align = 0 }); // Entry 132
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 186, minor_id = 1, fade_id = 16, align = 0 }); // Entry 133
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 186, minor_id = 11, fade_id = 16, align = 0 }); // Entry 134
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 187, minor_id = 1, fade_id = 27, align = 0 }); // Entry 135
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 187, minor_id = 2, fade_id = 16, align = 0 }); // Entry 136
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 188, minor_id = 1, fade_id = 2, align = 0 }); // Entry 137
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 189, minor_id = 1, fade_id = 16, align = 0 }); // Entry 138
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 189, minor_id = 101, fade_id = 1, align = 0 }); // Entry 139
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 190, minor_id = 1, fade_id = 21, align = 0 }); // Entry 140
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 191, minor_id = 1, fade_id = 16, align = 0 }); // Entry 141
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 192, minor_id = 1, fade_id = 2, align = 0 }); // Entry 142
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 193, minor_id = 1, fade_id = 16, align = 0 }); // Entry 143
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 193, minor_id = 105, fade_id = 8, align = 0 }); // Entry 144
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 193, minor_id = 106, fade_id = 8, align = 0 }); // Entry 145
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 194, minor_id = 1, fade_id = 23, align = 0 }); // Entry 146
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 194, minor_id = 101, fade_id = 16, align = 0 }); // Entry 147
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 195, minor_id = 1, fade_id = 16, align = 0 }); // Entry 148
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 196, minor_id = 1, fade_id = 23, align = 0 }); // Entry 149
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 196, minor_id = 101, fade_id = 8, align = 0 }); // Entry 150
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 196, minor_id = 201, fade_id = 16, align = 0 }); // Entry 151
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 197, minor_id = 1, fade_id = 16, align = 0 }); // Entry 152
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 197, minor_id = 2, fade_id = 16, align = 0 }); // Entry 153
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 198, minor_id = 1, fade_id = 2, align = 0 }); // Entry 154
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 199, minor_id = 1, fade_id = 8, align = 0 }); // Entry 155
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 199, minor_id = 2, fade_id = 2, align = 0 }); // Entry 156
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 200, minor_id = 1, fade_id = 16, align = 0 }); // Entry 157
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 201, minor_id = 1, fade_id = 16, align = 0 }); // Entry 158
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 202, minor_id = 1, fade_id = 16, align = 0 }); // Entry 159
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 203, minor_id = 1, fade_id = 16, align = 0 }); // Entry 160
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 204, minor_id = 1, fade_id = 16, align = 0 }); // Entry 161
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 205, minor_id = 1, fade_id = 16, align = 0 }); // Entry 162
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 206, minor_id = 1, fade_id = 16, align = 0 }); // Entry 163
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 207, minor_id = 1, fade_id = 16, align = 0 }); // Entry 164
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 208, minor_id = 1, fade_id = 1, align = 0 }); // Entry 165
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 209, minor_id = 1, fade_id = 23, align = 0 }); // Entry 166
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 210, minor_id = 1, fade_id = 16, align = 0 }); // Entry 167
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 210, minor_id = 101, fade_id = 16, align = 0 }); // Entry 168
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 211, minor_id = 1, fade_id = 16, align = 0 }); // Entry 169
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 211, minor_id = 201, fade_id = 16, align = 0 }); // Entry 170
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 212, minor_id = 1, fade_id = 23, align = 0 }); // Entry 171
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 213, minor_id = 1, fade_id = 21, align = 0 }); // Entry 172
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 215, minor_id = 1, fade_id = 1, align = 0 }); // Entry 173
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 216, minor_id = 1, fade_id = 23, align = 0 }); // Entry 174
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 216, minor_id = 101, fade_id = 16, align = 0 }); // Entry 175
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 217, minor_id = 1, fade_id = 16, align = 0 }); // Entry 176
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 217, minor_id = 11, fade_id = 16, align = 0 }); // Entry 177
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 218, minor_id = 1, fade_id = 16, align = 0 }); // Entry 178
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 218, minor_id = 2, fade_id = 16, align = 0 }); // Entry 179
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 218, minor_id = 3, fade_id = 16, align = 0 }); // Entry 180
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 218, minor_id = 12, fade_id = 1, align = 0 }); // Entry 181
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 219, minor_id = 1, fade_id = 16, align = 0 }); // Entry 182
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 220, minor_id = 1, fade_id = 21, align = 0 }); // Entry 183
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 220, minor_id = 2, fade_id = 16, align = 0 }); // Entry 184
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 220, minor_id = 3, fade_id = 16, align = 0 }); // Entry 185
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 221, minor_id = 1, fade_id = 2, align = 0 }); // Entry 186
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 221, minor_id = 2, fade_id = 16, align = 0 }); // Entry 187
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 221, minor_id = 101, fade_id = 16, align = 0 }); // Entry 188
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 221, minor_id = 102, fade_id = 16, align = 0 }); // Entry 189
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 222, minor_id = 1, fade_id = 16, align = 0 }); // Entry 190
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 222, minor_id = 2, fade_id = 8, align = 0 }); // Entry 191
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 222, minor_id = 3, fade_id = 16, align = 0 }); // Entry 192
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 222, minor_id = 4, fade_id = 16, align = 0 }); // Entry 193
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 223, minor_id = 1, fade_id = 8, align = 0 }); // Entry 194
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 225, minor_id = 1, fade_id = 16, align = 0 }); // Entry 195
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 226, minor_id = 1, fade_id = 8, align = 0 }); // Entry 196
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 227, minor_id = 1, fade_id = 16, align = 0 }); // Entry 197
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 228, minor_id = 1, fade_id = 16, align = 0 }); // Entry 198
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 229, minor_id = 1, fade_id = 1, align = 0 }); // Entry 199
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 229, minor_id = 2, fade_id = 2, align = 0 }); // Entry 200
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 230, minor_id = 201, fade_id = 16, align = 0 }); // Entry 201
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 230, minor_id = 301, fade_id = 16, align = 0 }); // Entry 202
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 233, minor_id = 1, fade_id = 16, align = 0 }); // Entry 203
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 234, minor_id = 1, fade_id = 16, align = 0 }); // Entry 204
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 234, minor_id = 11, fade_id = 1, align = 0 }); // Entry 205
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 236, minor_id = 1, fade_id = 16, align = 0 }); // Entry 206
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 237, minor_id = 1, fade_id = 16, align = 0 }); // Entry 207
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 239, minor_id = 1, fade_id = 8, align = 0 }); // Entry 208
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 240, minor_id = 1, fade_id = 2, align = 0 }); // Entry 209
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 241, minor_id = 1, fade_id = 8, align = 0 }); // Entry 210
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 242, minor_id = 1, fade_id = 21, align = 0 }); // Entry 211
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 243, minor_id = 1, fade_id = 16, align = 0 }); // Entry 212
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 243, minor_id = 2, fade_id = 16, align = 0 }); // Entry 213
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 243, minor_id = 211, fade_id = 8, align = 0 }); // Entry 214
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 243, minor_id = 308, fade_id = 2, align = 0 }); // Entry 215
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 243, minor_id = 401, fade_id = 8, align = 0 }); // Entry 216
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 244, minor_id = 1, fade_id = 8, align = 0 }); // Entry 217
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 244, minor_id = 2, fade_id = 1, align = 0 }); // Entry 218
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 244, minor_id = 3, fade_id = 16, align = 0 }); // Entry 219
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 244, minor_id = 101, fade_id = 16, align = 0 }); // Entry 220
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 244, minor_id = 103, fade_id = 8, align = 0 }); // Entry 221
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 244, minor_id = 201, fade_id = 2, align = 0 }); // Entry 222
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 244, minor_id = 401, fade_id = 2, align = 0 }); // Entry 223
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 245, minor_id = 1, fade_id = 23, align = 0 }); // Entry 224
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 246, minor_id = 1, fade_id = 16, align = 0 }); // Entry 225
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 247, minor_id = 1, fade_id = 16, align = 0 }); // Entry 226
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 247, minor_id = 101, fade_id = 16, align = 0 }); // Entry 227
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 248, minor_id = 1, fade_id = 1, align = 0 }); // Entry 228
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 249, minor_id = 1, fade_id = 2, align = 0 }); // Entry 229
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 249, minor_id = 101, fade_id = 16, align = 0 }); // Entry 230
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 250, minor_id = 1, fade_id = 16, align = 0 }); // Entry 231
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 251, minor_id = 1, fade_id = 16, align = 0 }); // Entry 232
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 253, minor_id = 1, fade_id = 16, align = 0 }); // Entry 233
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 254, minor_id = 1, fade_id = 23, align = 0 }); // Entry 234
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 255, minor_id = 1, fade_id = 16, align = 0 }); // Entry 235
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 256, minor_id = 1, fade_id = 16, align = 0 }); // Entry 236
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 257, minor_id = 1, fade_id = 1, align = 0 }); // Entry 237
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 257, minor_id = 3, fade_id = 23, align = 0 }); // Entry 238
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 258, minor_id = 1, fade_id = 8, align = 0 }); // Entry 239
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 258, minor_id = 101, fade_id = 1, align = 0 }); // Entry 240
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 258, minor_id = 201, fade_id = 16, align = 0 }); // Entry 241
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 259, minor_id = 401, fade_id = 16, align = 0 }); // Entry 242
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 260, minor_id = 1, fade_id = 16, align = 0 }); // Entry 243
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 261, minor_id = 1, fade_id = 16, align = 0 }); // Entry 244
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 262, minor_id = 1, fade_id = 21, align = 0 }); // Entry 245
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 263, minor_id = 101, fade_id = 16, align = 0 }); // Entry 246
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 264, minor_id = 1, fade_id = 1, align = 0 }); // Entry 247
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 265, minor_id = 1, fade_id = 24, align = 0 }); // Entry 248
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 266, minor_id = 1, fade_id = 16, align = 0 }); // Entry 249
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 266, minor_id = 2, fade_id = 16, align = 0 }); // Entry 250
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 266, minor_id = 12, fade_id = 16, align = 0 }); // Entry 251
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 267, minor_id = 1, fade_id = 16, align = 0 }); // Entry 252
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 267, minor_id = 2, fade_id = 16, align = 0 }); // Entry 253
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 267, minor_id = 3, fade_id = 16, align = 0 }); // Entry 254
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 267, minor_id = 4, fade_id = 16, align = 0 }); // Entry 255
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 267, minor_id = 5, fade_id = 16, align = 0 }); // Entry 256
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 267, minor_id = 12, fade_id = 1, align = 0 }); // Entry 257
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 268, minor_id = 1, fade_id = 16, align = 0 }); // Entry 258
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 268, minor_id = 2, fade_id = 16, align = 0 }); // Entry 259
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 269, minor_id = 1, fade_id = 16, align = 0 }); // Entry 260
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 269, minor_id = 2, fade_id = 1, align = 0 }); // Entry 261
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 270, minor_id = 1, fade_id = 16, align = 0 }); // Entry 262
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 270, minor_id = 101, fade_id = 16, align = 0 }); // Entry 263
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 271, minor_id = 1, fade_id = 16, align = 0 }); // Entry 264
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 271, minor_id = 101, fade_id = 16, align = 0 }); // Entry 265
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 272, minor_id = 1, fade_id = 16, align = 0 }); // Entry 266
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 272, minor_id = 11, fade_id = 1, align = 0 }); // Entry 267
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 272, minor_id = 101, fade_id = 16, align = 0 }); // Entry 268
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 272, minor_id = 201, fade_id = 16, align = 0 }); // Entry 269
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 273, minor_id = 1, fade_id = 16, align = 0 }); // Entry 270
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 273, minor_id = 201, fade_id = 16, align = 0 }); // Entry 271
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 273, minor_id = 301, fade_id = 16, align = 0 }); // Entry 272
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 274, minor_id = 1, fade_id = 16, align = 0 }); // Entry 273
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 274, minor_id = 101, fade_id = 16, align = 0 }); // Entry 274
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 274, minor_id = 201, fade_id = 16, align = 0 }); // Entry 275
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 275, minor_id = 1, fade_id = 1, align = 0 }); // Entry 276
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 276, minor_id = 1, fade_id = 16, align = 0 }); // Entry 277
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 277, minor_id = 1, fade_id = 16, align = 0 }); // Entry 278
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 277, minor_id = 101, fade_id = 16, align = 0 }); // Entry 279
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 277, minor_id = 201, fade_id = 16, align = 0 }); // Entry 280
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 278, minor_id = 1, fade_id = 16, align = 0 }); // Entry 281
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 279, minor_id = 1, fade_id = 16, align = 0 }); // Entry 282
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 279, minor_id = 101, fade_id = 16, align = 0 }); // Entry 283
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 280, minor_id = 1, fade_id = 16, align = 0 }); // Entry 284
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 280, minor_id = 101, fade_id = 16, align = 0 }); // Entry 285
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 280, minor_id = 201, fade_id = 16, align = 0 }); // Entry 286
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 281, minor_id = 1, fade_id = 8, align = 0 }); // Entry 287
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 282, minor_id = 1, fade_id = 16, align = 0 }); // Entry 288
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 283, minor_id = 1, fade_id = 8, align = 0 }); // Entry 289
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 284, minor_id = 1, fade_id = 2, align = 0 }); // Entry 290
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 284, minor_id = 101, fade_id = 16, align = 0 }); // Entry 291
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 285, minor_id = 1, fade_id = 16, align = 0 }); // Entry 292
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 286, minor_id = 1, fade_id = 2, align = 0 }); // Entry 293
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 287, minor_id = 1, fade_id = 16, align = 0 }); // Entry 294
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 288, minor_id = 2, fade_id = 1, align = 0 }); // Entry 295
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 288, minor_id = 101, fade_id = 16, align = 0 }); // Entry 296
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 288, minor_id = 201, fade_id = 21, align = 0 }); // Entry 297
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 289, minor_id = 1, fade_id = 16, align = 0 }); // Entry 298
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 289, minor_id = 101, fade_id = 16, align = 0 }); // Entry 299
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 290, minor_id = 1, fade_id = 23, align = 0 }); // Entry 300
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 292, minor_id = 1, fade_id = 1, align = 0 }); // Entry 301
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 293, minor_id = 1, fade_id = 16, align = 0 }); // Entry 302
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 294, minor_id = 1, fade_id = 16, align = 0 }); // Entry 303
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 295, minor_id = 1, fade_id = 16, align = 0 }); // Entry 304
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 295, minor_id = 1, fade_id = 16, align = 0 }); // Entry 305
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 295, minor_id = 2, fade_id = 16, align = 0 }); // Entry 306
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 295, minor_id = 50, fade_id = 16, align = 0 }); // Entry 307
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 295, minor_id = 101, fade_id = 16, align = 0 }); // Entry 308
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 295, minor_id = 301, fade_id = 16, align = 0 }); // Entry 309
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 296, minor_id = 1, fade_id = 21, align = 0 }); // Entry 310
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 297, minor_id = 1, fade_id = 16, align = 0 }); // Entry 311
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 297, minor_id = 2, fade_id = 23, align = 0 }); // Entry 312
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 297, minor_id = 101, fade_id = 16, align = 0 }); // Entry 313
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 298, minor_id = 1, fade_id = 16, align = 0 }); // Entry 314
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 298, minor_id = 101, fade_id = 16, align = 0 }); // Entry 315
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 299, minor_id = 1, fade_id = 1, align = 0 }); // Entry 316
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 300, minor_id = 1, fade_id = 16, align = 0 }); // Entry 317
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 301, minor_id = 1, fade_id = 1, align = 0 }); // Entry 318
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 302, minor_id = 1, fade_id = 16, align = 0 }); // Entry 319
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 303, minor_id = 1, fade_id = 1, align = 0 }); // Entry 320
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 304, minor_id = 1, fade_id = 16, align = 0 }); // Entry 321
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 305, minor_id = 1, fade_id = 16, align = 0 }); // Entry 322
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 307, minor_id = 1, fade_id = 2, align = 0 }); // Entry 323
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 307, minor_id = 2, fade_id = 16, align = 0 }); // Entry 324
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 307, minor_id = 3, fade_id = 2, align = 0 }); // Entry 325
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 308, minor_id = 1, fade_id = 21, align = 0 }); // Entry 326
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 308, minor_id = 2, fade_id = 1, align = 0 }); // Entry 327
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 308, minor_id = 12, fade_id = 1, align = 0 }); // Entry 328
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 308, minor_id = 101, fade_id = 16, align = 0 }); // Entry 329
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 309, minor_id = 1, fade_id = 16, align = 0 }); // Entry 330
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 309, minor_id = 101, fade_id = 16, align = 0 }); // Entry 331
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 309, minor_id = 201, fade_id = 16, align = 0 }); // Entry 332
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 309, minor_id = 301, fade_id = 16, align = 0 }); // Entry 333
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 309, minor_id = 401, fade_id = 16, align = 0 }); // Entry 334
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 309, minor_id = 501, fade_id = 16, align = 0 }); // Entry 335
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 309, minor_id = 601, fade_id = 16, align = 0 }); // Entry 336
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 309, minor_id = 602, fade_id = 16, align = 0 }); // Entry 337
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 309, minor_id = 603, fade_id = 16, align = 0 }); // Entry 338
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 309, minor_id = 701, fade_id = 8, align = 0 }); // Entry 339
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 310, minor_id = 1, fade_id = 16, align = 0 }); // Entry 340
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 310, minor_id = 2, fade_id = 16, align = 0 }); // Entry 341
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 310, minor_id = 101, fade_id = 16, align = 0 }); // Entry 342
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 310, minor_id = 103, fade_id = 16, align = 0 }); // Entry 343
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 311, minor_id = 1, fade_id = 16, align = 0 }); // Entry 344
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 311, minor_id = 2, fade_id = 1, align = 0 }); // Entry 345
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 311, minor_id = 11, fade_id = 1, align = 0 }); // Entry 346
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 311, minor_id = 102, fade_id = 16, align = 0 }); // Entry 347
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 311, minor_id = 103, fade_id = 16, align = 0 }); // Entry 348
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 311, minor_id = 104, fade_id = 1, align = 0 }); // Entry 349
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 311, minor_id = 203, fade_id = 16, align = 0 }); // Entry 350
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 312, minor_id = 1, fade_id = 16, align = 0 }); // Entry 351
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 312, minor_id = 101, fade_id = 8, align = 0 }); // Entry 352
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 313, minor_id = 1, fade_id = 16, align = 0 }); // Entry 353
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 313, minor_id = 2, fade_id = 8, align = 0 }); // Entry 354
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 313, minor_id = 101, fade_id = 2, align = 0 }); // Entry 355
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 314, minor_id = 1, fade_id = 16, align = 0 }); // Entry 356
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 315, minor_id = 1, fade_id = 16, align = 0 }); // Entry 357
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 315, minor_id = 2, fade_id = 16, align = 0 }); // Entry 358
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 315, minor_id = 101, fade_id = 16, align = 0 }); // Entry 359
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 315, minor_id = 301, fade_id = 16, align = 0 }); // Entry 360
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 316, minor_id = 1, fade_id = 1, align = 0 }); // Entry 361
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 317, minor_id = 1, fade_id = 2, align = 0 }); // Entry 362
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 317, minor_id = 101, fade_id = 16, align = 0 }); // Entry 363
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 317, minor_id = 201, fade_id = 16, align = 0 }); // Entry 364
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 318, minor_id = 1, fade_id = 1, align = 0 }); // Entry 365
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 318, minor_id = 101, fade_id = 2, align = 0 }); // Entry 366
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 319, minor_id = 1, fade_id = 16, align = 0 }); // Entry 367
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 319, minor_id = 2, fade_id = 2, align = 0 }); // Entry 368
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 319, minor_id = 3, fade_id = 1, align = 0 }); // Entry 369
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 319, minor_id = 10, fade_id = 1, align = 0 }); // Entry 370
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 319, minor_id = 13, fade_id = 1, align = 0 }); // Entry 371
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 319, minor_id = 23, fade_id = 1, align = 0 }); // Entry 372
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 319, minor_id = 101, fade_id = 2, align = 0 }); // Entry 373
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 320, minor_id = 1, fade_id = 16, align = 0 }); // Entry 374
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 320, minor_id = 101, fade_id = 2, align = 0 }); // Entry 375
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 320, minor_id = 103, fade_id = 16, align = 0 }); // Entry 376
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 320, minor_id = 201, fade_id = 2, align = 0 }); // Entry 377
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 320, minor_id = 401, fade_id = 16, align = 0 }); // Entry 378
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 320, minor_id = 501, fade_id = 20, align = 0 }); // Entry 379
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 320, minor_id = 502, fade_id = 20, align = 0 }); // Entry 380
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 321, minor_id = 1, fade_id = 16, align = 0 }); // Entry 381
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 322, minor_id = 1, fade_id = 16, align = 0 }); // Entry 382
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 322, minor_id = 2, fade_id = 16, align = 0 }); // Entry 383
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 322, minor_id = 101, fade_id = 16, align = 0 }); // Entry 384
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 324, minor_id = 1, fade_id = 16, align = 0 }); // Entry 385
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 325, minor_id = 1, fade_id = 1, align = 0 }); // Entry 386
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 325, minor_id = 2, fade_id = 16, align = 0 }); // Entry 387
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 325, minor_id = 101, fade_id = 8, align = 0 }); // Entry 388
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 326, minor_id = 1, fade_id = 16, align = 0 }); // Entry 389
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 327, minor_id = 1, fade_id = 23, align = 0 }); // Entry 390
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 328, minor_id = 1, fade_id = 16, align = 0 }); // Entry 391
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 328, minor_id = 2, fade_id = 16, align = 0 }); // Entry 392
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 329, minor_id = 1, fade_id = 16, align = 0 }); // Entry 393
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 330, minor_id = 1, fade_id = 16, align = 0 }); // Entry 394
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 331, minor_id = 1, fade_id = 16, align = 0 }); // Entry 395
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 332, minor_id = 1, fade_id = 16, align = 0 }); // Entry 396
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 333, minor_id = 1, fade_id = 16, align = 0 }); // Entry 397
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 333, minor_id = 101, fade_id = 16, align = 0 }); // Entry 398
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 333, minor_id = 301, fade_id = 16, align = 0 }); // Entry 399
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 334, minor_id = 1, fade_id = 16, align = 0 }); // Entry 400
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 334, minor_id = 201, fade_id = 16, align = 0 }); // Entry 401
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 335, minor_id = 1, fade_id = 8, align = 0 }); // Entry 402
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 336, minor_id = 1, fade_id = 16, align = 0 }); // Entry 403
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 337, minor_id = 1, fade_id = 16, align = 0 }); // Entry 404
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 338, minor_id = 1, fade_id = 16, align = 0 }); // Entry 405
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 339, minor_id = 1, fade_id = 16, align = 0 }); // Entry 406
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 340, minor_id = 1, fade_id = 1, align = 0 }); // Entry 407
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 341, minor_id = 1, fade_id = 16, align = 0 }); // Entry 408
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 342, minor_id = 1, fade_id = 16, align = 0 }); // Entry 409
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 342, minor_id = 101, fade_id = 16, align = 0 }); // Entry 410
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 342, minor_id = 201, fade_id = 16, align = 0 }); // Entry 411
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 343, minor_id = 1, fade_id = 23, align = 0 }); // Entry 412
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 343, minor_id = 301, fade_id = 1, align = 0 }); // Entry 413
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 344, minor_id = 1, fade_id = 1, align = 0 }); // Entry 414
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 345, minor_id = 1, fade_id = 16, align = 0 }); // Entry 415
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 345, minor_id = 2, fade_id = 16, align = 0 }); // Entry 416
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 346, minor_id = 1, fade_id = 16, align = 0 }); // Entry 417
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 346, minor_id = 11, fade_id = 16, align = 0 }); // Entry 418
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 347, minor_id = 1, fade_id = 16, align = 0 }); // Entry 419
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 347, minor_id = 11, fade_id = 16, align = 0 }); // Entry 420
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 347, minor_id = 2, fade_id = 1, align = 0 }); // Entry 421
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 348, minor_id = 101, fade_id = 8, align = 0 }); // Entry 422
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 348, minor_id = 201, fade_id = 16, align = 0 }); // Entry 423
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 349, minor_id = 1, fade_id = 8, align = 0 }); // Entry 424
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 349, minor_id = 2, fade_id = 1, align = 0 }); // Entry 425
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 349, minor_id = 4, fade_id = 16, align = 0 }); // Entry 426
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 349, minor_id = 5, fade_id = 1, align = 0 }); // Entry 427
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 349, minor_id = 6, fade_id = 1, align = 0 }); // Entry 428
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 350, minor_id = 1, fade_id = 16, align = 0 }); // Entry 429
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 350, minor_id = 11, fade_id = 1, align = 0 }); // Entry 430
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 351, minor_id = 1, fade_id = 1, align = 0 }); // Entry 431
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 352, minor_id = 1, fade_id = 21, align = 0 }); // Entry 432
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 354, minor_id = 1, fade_id = 21, align = 0 }); // Entry 433
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 355, minor_id = 1, fade_id = 16, align = 0 }); // Entry 434
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 355, minor_id = 2, fade_id = 16, align = 0 }); // Entry 435
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 355, minor_id = 3, fade_id = 16, align = 0 }); // Entry 436
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 355, minor_id = 101, fade_id = 16, align = 0 }); // Entry 437
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 355, minor_id = 201, fade_id = 16, align = 0 }); // Entry 438
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 355, minor_id = 301, fade_id = 16, align = 0 }); // Entry 439
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 355, minor_id = 401, fade_id = 16, align = 0 }); // Entry 440
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 356, minor_id = 1, fade_id = 16, align = 0 }); // Entry 441
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 357, minor_id = 1, fade_id = 16, align = 0 }); // Entry 442
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 357, minor_id = 2, fade_id = 16, align = 0 }); // Entry 443
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 357, minor_id = 101, fade_id = 16, align = 0 }); // Entry 444
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 357, minor_id = 102, fade_id = 1, align = 0 }); // Entry 445
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 357, minor_id = 201, fade_id = 16, align = 0 }); // Entry 446
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 357, minor_id = 301, fade_id = 16, align = 0 }); // Entry 447
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 359, minor_id = 1, fade_id = 16, align = 0 }); // Entry 448
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 359, minor_id = 2, fade_id = 16, align = 0 }); // Entry 449
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 359, minor_id = 12, fade_id = 16, align = 0 }); // Entry 450
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 360, minor_id = 101, fade_id = 16, align = 0 }); // Entry 451
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 360, minor_id = 102, fade_id = 16, align = 0 }); // Entry 452
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 360, minor_id = 201, fade_id = 16, align = 0 }); // Entry 453
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 361, minor_id = 101, fade_id = 16, align = 0 }); // Entry 454
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 362, minor_id = 1, fade_id = 8, align = 0 }); // Entry 455
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 364, minor_id = 1, fade_id = 16, align = 0 }); // Entry 456
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 365, minor_id = 1, fade_id = 1, align = 0 }); // Entry 457
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 366, minor_id = 1, fade_id = 16, align = 0 }); // Entry 458
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 367, minor_id = 1, fade_id = 16, align = 0 }); // Entry 459
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 368, minor_id = 1, fade_id = 8, align = 0 }); // Entry 460
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 368, minor_id = 2, fade_id = 16, align = 0 }); // Entry 461
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 369, minor_id = 1, fade_id = 16, align = 0 }); // Entry 462
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 369, minor_id = 101, fade_id = 16, align = 0 }); // Entry 463
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 369, minor_id = 201, fade_id = 16, align = 0 }); // Entry 464
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 370, minor_id = 1, fade_id = 2, align = 0 }); // Entry 465
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 370, minor_id = 2, fade_id = 2, align = 0 }); // Entry 466
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 370, minor_id = 3, fade_id = 2, align = 0 }); // Entry 467
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 371, minor_id = 1, fade_id = 16, align = 0 }); // Entry 468
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 372, minor_id = 1, fade_id = 1, align = 0 }); // Entry 469
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 373, minor_id = 1, fade_id = 16, align = 0 }); // Entry 470
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 374, minor_id = 2, fade_id = 16, align = 0 }); // Entry 471
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 375, minor_id = 1, fade_id = 16, align = 0 }); // Entry 472
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 375, minor_id = 101, fade_id = 16, align = 0 }); // Entry 473
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 376, minor_id = 1, fade_id = 21, align = 0 }); // Entry 474
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 376, minor_id = 2, fade_id = 16, align = 0 }); // Entry 475
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 377, minor_id = 1, fade_id = 1, align = 0 }); // Entry 476
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 377, minor_id = 3, fade_id = 16, align = 0 }); // Entry 477
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 377, minor_id = 101, fade_id = 2, align = 0 }); // Entry 478
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 378, minor_id = 1, fade_id = 24, align = 0 }); // Entry 479
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 379, minor_id = 1, fade_id = 21, align = 0 }); // Entry 480
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 379, minor_id = 101, fade_id = 16, align = 0 }); // Entry 481
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 379, minor_id = 201, fade_id = 16, align = 0 }); // Entry 482
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 379, minor_id = 203, fade_id = 16, align = 0 }); // Entry 483
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 379, minor_id = 204, fade_id = 16, align = 0 }); // Entry 484
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 379, minor_id = 220, fade_id = 16, align = 0 }); // Entry 485
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 380, minor_id = 1, fade_id = 16, align = 0 }); // Entry 486
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 381, minor_id = 1, fade_id = 16, align = 0 }); // Entry 487
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 381, minor_id = 301, fade_id = 16, align = 0 }); // Entry 488
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 382, minor_id = 1, fade_id = 16, align = 0 }); // Entry 489
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 382, minor_id = 400, fade_id = 16, align = 0 }); // Entry 490
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 383, minor_id = 1, fade_id = 16, align = 0 }); // Entry 491
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 383, minor_id = 2, fade_id = 16, align = 0 }); // Entry 492
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 383, minor_id = 5, fade_id = 16, align = 0 }); // Entry 493
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 384, minor_id = 1, fade_id = 16, align = 0 }); // Entry 494
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 384, minor_id = 101, fade_id = 16, align = 0 }); // Entry 495
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 385, minor_id = 1, fade_id = 16, align = 0 }); // Entry 496
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 386, minor_id = 1, fade_id = 16, align = 0 }); // Entry 497
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 386, minor_id = 2, fade_id = 16, align = 0 }); // Entry 498
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 387, minor_id = 1, fade_id = 16, align = 0 }); // Entry 499
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 387, minor_id = 2, fade_id = 16, align = 0 }); // Entry 500
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 388, minor_id = 1, fade_id = 1, align = 0 }); // Entry 501
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 389, minor_id = 1, fade_id = 1, align = 0 }); // Entry 502
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 389, minor_id = 10, fade_id = 1, align = 0 }); // Entry 503
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 389, minor_id = 20, fade_id = 18, align = 0 }); // Entry 504
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 390, minor_id = 1, fade_id = 16, align = 0 }); // Entry 505
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 390, minor_id = 101, fade_id = 16, align = 0 }); // Entry 506
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 391, minor_id = 1, fade_id = 16, align = 0 }); // Entry 507
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 392, minor_id = 1, fade_id = 1, align = 0 }); // Entry 508
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 392, minor_id = 2, fade_id = 1, align = 0 }); // Entry 509
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 393, minor_id = 1, fade_id = 27, align = 0 }); // Entry 510
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 393, minor_id = 2, fade_id = 16, align = 0 }); // Entry 511
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 393, minor_id = 3, fade_id = 16, align = 0 }); // Entry 512
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 393, minor_id = 4, fade_id = 16, align = 0 }); // Entry 513
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 393, minor_id = 5, fade_id = 1, align = 0 }); // Entry 514
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 393, minor_id = 6, fade_id = 16, align = 0 }); // Entry 515
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 393, minor_id = 15, fade_id = 1, align = 0 }); // Entry 516
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 394, minor_id = 1, fade_id = 16, align = 0 }); // Entry 517
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 394, minor_id = 2, fade_id = 16, align = 0 }); // Entry 518
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 394, minor_id = 101, fade_id = 16, align = 0 }); // Entry 519
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 394, minor_id = 201, fade_id = 16, align = 0 }); // Entry 520
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 394, minor_id = 301, fade_id = 16, align = 0 }); // Entry 521
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 395, minor_id = 1, fade_id = 27, align = 0 }); // Entry 522
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 395, minor_id = 2, fade_id = 16, align = 0 }); // Entry 523
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 395, minor_id = 3, fade_id = 16, align = 0 }); // Entry 524
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 395, minor_id = 4, fade_id = 16, align = 0 }); // Entry 525
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 395, minor_id = 5, fade_id = 16, align = 0 }); // Entry 526
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 395, minor_id = 6, fade_id = 16, align = 0 }); // Entry 527
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 396, minor_id = 1, fade_id = 16, align = 0 }); // Entry 528
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 397, minor_id = 1, fade_id = 16, align = 0 }); // Entry 529
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 399, minor_id = 1, fade_id = 16, align = 0 }); // Entry 530
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 399, minor_id = 2, fade_id = 16, align = 0 }); // Entry 531
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 400, minor_id = 1, fade_id = 16, align = 0 }); // Entry 532
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 400, minor_id = 2, fade_id = 16, align = 0 }); // Entry 533
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 401, minor_id = 1, fade_id = 16, align = 0 }); // Entry 534
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 401, minor_id = 2, fade_id = 2, align = 0 }); // Entry 535
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 401, minor_id = 3, fade_id = 16, align = 0 }); // Entry 536
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 402, minor_id = 1, fade_id = 16, align = 0 }); // Entry 537
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 403, minor_id = 1, fade_id = 16, align = 0 }); // Entry 538
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 403, minor_id = 2, fade_id = 8, align = 0 }); // Entry 539
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 403, minor_id = 101, fade_id = 16, align = 0 }); // Entry 540
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 404, minor_id = 1, fade_id = 23, align = 0 }); // Entry 541
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 405, minor_id = 1, fade_id = 1, align = 0 }); // Entry 542
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 406, minor_id = 1, fade_id = 1, align = 0 }); // Entry 543
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 407, minor_id = 1, fade_id = 16, align = 0 }); // Entry 544
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 407, minor_id = 101, fade_id = 16, align = 0 }); // Entry 545
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 407, minor_id = 301, fade_id = 16, align = 0 }); // Entry 546
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 408, minor_id = 1, fade_id = 16, align = 0 }); // Entry 547
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 408, minor_id = 2, fade_id = 16, align = 0 }); // Entry 548
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 408, minor_id = 101, fade_id = 16, align = 0 }); // Entry 549
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 408, minor_id = 201, fade_id = 16, align = 0 }); // Entry 550
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 408, minor_id = 301, fade_id = 16, align = 0 }); // Entry 551
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 409, minor_id = 1, fade_id = 16, align = 0 }); // Entry 552
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 409, minor_id = 32, fade_id = 16, align = 0 }); // Entry 553
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 409, minor_id = 40, fade_id = 16, align = 0 }); // Entry 554
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 409, minor_id = 101, fade_id = 16, align = 0 }); // Entry 555
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 409, minor_id = 201, fade_id = 16, align = 0 }); // Entry 556
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 410, minor_id = 1, fade_id = 16, align = 0 }); // Entry 557
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 410, minor_id = 2, fade_id = 16, align = 0 }); // Entry 558
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 410, minor_id = 101, fade_id = 16, align = 0 }); // Entry 559
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 411, minor_id = 1, fade_id = 16, align = 0 }); // Entry 560
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 411, minor_id = 101, fade_id = 16, align = 0 }); // Entry 561
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 411, minor_id = 201, fade_id = 16, align = 0 }); // Entry 562
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 412, minor_id = 1, fade_id = 16, align = 0 }); // Entry 563
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 412, minor_id = 201, fade_id = 16, align = 0 }); // Entry 564
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 412, minor_id = 301, fade_id = 16, align = 0 }); // Entry 565
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 414, minor_id = 1, fade_id = 16, align = 0 }); // Entry 566
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 415, minor_id = 1, fade_id = 16, align = 0 }); // Entry 567
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 416, minor_id = 1, fade_id = 16, align = 0 }); // Entry 568
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 417, minor_id = 1, fade_id = 16, align = 0 }); // Entry 569
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 419, minor_id = 1, fade_id = 16, align = 0 }); // Entry 570
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 420, minor_id = 1, fade_id = 8, align = 0 }); // Entry 571
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 421, minor_id = 1, fade_id = 16, align = 0 }); // Entry 572
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 421, minor_id = 101, fade_id = 16, align = 0 }); // Entry 573
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 422, minor_id = 1, fade_id = 16, align = 0 }); // Entry 574
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 422, minor_id = 2, fade_id = 1, align = 0 }); // Entry 575
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 422, minor_id = 3, fade_id = 16, align = 0 }); // Entry 576
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 423, minor_id = 1, fade_id = 16, align = 0 }); // Entry 577
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 423, minor_id = 31, fade_id = 16, align = 0 }); // Entry 578
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 424, minor_id = 1, fade_id = 1, align = 0 }); // Entry 579
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 424, minor_id = 2, fade_id = 16, align = 0 }); // Entry 580
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 424, minor_id = 4, fade_id = 16, align = 0 }); // Entry 581
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 425, minor_id = 1, fade_id = 16, align = 0 }); // Entry 582
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 426, minor_id = 1, fade_id = 16, align = 0 }); // Entry 583
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 427, minor_id = 1, fade_id = 16, align = 0 }); // Entry 584
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 428, minor_id = 1, fade_id = 1, align = 0 }); // Entry 585
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 430, minor_id = 1, fade_id = 16, align = 0 }); // Entry 586
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 431, minor_id = 1, fade_id = 16, align = 0 }); // Entry 587
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 431, minor_id = 2, fade_id = 16, align = 0 }); // Entry 588
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 431, minor_id = 3, fade_id = 1, align = 0 }); // Entry 589
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 431, minor_id = 12, fade_id = 16, align = 0 }); // Entry 590
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 432, minor_id = 1, fade_id = 16, align = 0 }); // Entry 591
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 433, minor_id = 1, fade_id = 16, align = 0 }); // Entry 592
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 434, minor_id = 1, fade_id = 16, align = 0 }); // Entry 593
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 434, minor_id = 2, fade_id = 16, align = 0 }); // Entry 594
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 434, minor_id = 3, fade_id = 1, align = 0 }); // Entry 595
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 434, minor_id = 4, fade_id = 16, align = 0 }); // Entry 596
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 435, minor_id = 1, fade_id = 22, align = 0 }); // Entry 597
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 436, minor_id = 1, fade_id = 1, align = 0 }); // Entry 598
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 437, minor_id = 1, fade_id = 16, align = 0 }); // Entry 599
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 438, minor_id = 1, fade_id = 16, align = 0 }); // Entry 600
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 440, minor_id = 1, fade_id = 16, align = 0 }); // Entry 601
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 441, minor_id = 1, fade_id = 16, align = 0 }); // Entry 602
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 442, minor_id = 1, fade_id = 16, align = 0 }); // Entry 603
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 443, minor_id = 1, fade_id = 16, align = 0 }); // Entry 604
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 444, minor_id = 1, fade_id = 16, align = 0 }); // Entry 605
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 445, minor_id = 1, fade_id = 16, align = 0 }); // Entry 606
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 445, minor_id = 2, fade_id = 16, align = 0 }); // Entry 607
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 446, minor_id = 1, fade_id = 16, align = 0 }); // Entry 608
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 447, minor_id = 1, fade_id = 16, align = 0 }); // Entry 609
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 448, minor_id = 1, fade_id = 16, align = 0 }); // Entry 610
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 449, minor_id = 1, fade_id = 27, align = 0 }); // Entry 611
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 449, minor_id = 2, fade_id = 1, align = 0 }); // Entry 612
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 450, minor_id = 1, fade_id = 1, align = 0 }); // Entry 613
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 450, minor_id = 2, fade_id = 1, align = 0 }); // Entry 614
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 450, minor_id = 101, fade_id = 16, align = 0 }); // Entry 615
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 451, minor_id = 1, fade_id = 1, align = 0 }); // Entry 616
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 451, minor_id = 3, fade_id = 1, align = 0 }); // Entry 617
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 451, minor_id = 4, fade_id = 1, align = 0 }); // Entry 618
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 451, minor_id = 13, fade_id = 1, align = 0 }); // Entry 619
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 452, minor_id = 1, fade_id = 16, align = 0 }); // Entry 620
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 453, minor_id = 101, fade_id = 16, align = 0 }); // Entry 621
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 453, minor_id = 102, fade_id = 16, align = 0 }); // Entry 622
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 453, minor_id = 103, fade_id = 16, align = 0 }); // Entry 623
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 453, minor_id = 104, fade_id = 16, align = 0 }); // Entry 624
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 453, minor_id = 105, fade_id = 16, align = 0 }); // Entry 625
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 453, minor_id = 106, fade_id = 16, align = 0 }); // Entry 626
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 454, minor_id = 1, fade_id = 16, align = 0 }); // Entry 627
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 455, minor_id = 1, fade_id = 16, align = 0 }); // Entry 628
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 456, minor_id = 1, fade_id = 16, align = 0 }); // Entry 629
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 457, minor_id = 1, fade_id = 16, align = 0 }); // Entry 630
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 458, minor_id = 1, fade_id = 16, align = 0 }); // Entry 631
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 459, minor_id = 1, fade_id = 1, align = 0 }); // Entry 632
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 459, minor_id = 2, fade_id = 16, align = 0 }); // Entry 633
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 459, minor_id = 3, fade_id = 1, align = 0 }); // Entry 634
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 459, minor_id = 5, fade_id = 17, align = 0 }); // Entry 635
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 460, minor_id = 1, fade_id = 17, align = 0 }); // Entry 636
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 460, minor_id = 2, fade_id = 1, align = 0 }); // Entry 637
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 461, minor_id = 1, fade_id = 16, align = 0 }); // Entry 638
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 464, minor_id = 2, fade_id = 16, align = 0 }); // Entry 639
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 464, minor_id = 3, fade_id = 1, align = 0 }); // Entry 640
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 465, minor_id = 1, fade_id = 16, align = 0 }); // Entry 641
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 466, minor_id = 1, fade_id = 16, align = 0 }); // Entry 642
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 467, minor_id = 1, fade_id = 1, align = 0 }); // Entry 643
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 467, minor_id = 2, fade_id = 16, align = 0 }); // Entry 644
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 468, minor_id = 1, fade_id = 16, align = 0 }); // Entry 645
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 469, minor_id = 1, fade_id = 1, align = 0 }); // Entry 646
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 469, minor_id = 2, fade_id = 16, align = 0 }); // Entry 647
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 469, minor_id = 3, fade_id = 17, align = 0 }); // Entry 648
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 469, minor_id = 4, fade_id = 17, align = 0 }); // Entry 649
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 470, minor_id = 1, fade_id = 16, align = 0 }); // Entry 650
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 470, minor_id = 101, fade_id = 1, align = 0 }); // Entry 651
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 470, minor_id = 201, fade_id = 1, align = 0 }); // Entry 652
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 470, minor_id = 211, fade_id = 1, align = 0 }); // Entry 653
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 470, minor_id = 301, fade_id = 1, align = 0 }); // Entry 654
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 470, minor_id = 311, fade_id = 1, align = 0 }); // Entry 655
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 470, minor_id = 401, fade_id = 1, align = 0 }); // Entry 656
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 470, minor_id = 411, fade_id = 1, align = 0 }); // Entry 657
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 470, minor_id = 501, fade_id = 1, align = 0 }); // Entry 658
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 470, minor_id = 511, fade_id = 1, align = 0 }); // Entry 659
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 470, minor_id = 601, fade_id = 1, align = 0 }); // Entry 660
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 470, minor_id = 611, fade_id = 1, align = 0 }); // Entry 661
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 470, minor_id = 701, fade_id = 1, align = 0 }); // Entry 662
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 470, minor_id = 711, fade_id = 1, align = 0 }); // Entry 663
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 471, minor_id = 1, fade_id = 1, align = 0 }); // Entry 664
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 472, minor_id = 1, fade_id = 1, align = 0 }); // Entry 665
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 473, minor_id = 1, fade_id = 1, align = 0 }); // Entry 666
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 473, minor_id = 2, fade_id = 1, align = 0 }); // Entry 667
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 473, minor_id = 3, fade_id = 1, align = 0 }); // Entry 668
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 473, minor_id = 4, fade_id = 1, align = 0 }); // Entry 669
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 474, minor_id = 1, fade_id = 1, align = 0 }); // Entry 670
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 474, minor_id = 2, fade_id = 1, align = 0 }); // Entry 671
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 474, minor_id = 102, fade_id = 16, align = 0 }); // Entry 672
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 474, minor_id = 103, fade_id = 1, align = 0 }); // Entry 673
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 474, minor_id = 104, fade_id = 1, align = 0 }); // Entry 674
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 475, minor_id = 1, fade_id = 16, align = 0 }); // Entry 675
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 475, minor_id = 2, fade_id = 22, align = 0 }); // Entry 676
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 475, minor_id = 3, fade_id = 1, align = 0 }); // Entry 677
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 476, minor_id = 1, fade_id = 8, align = 0 }); // Entry 678
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 476, minor_id = 2, fade_id = 1, align = 0 }); // Entry 679
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 480, minor_id = 30, fade_id = 1, align = 0 }); // Entry 680
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 480, minor_id = 60, fade_id = 1, align = 0 }); // Entry 681
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 480, minor_id = 80, fade_id = 16, align = 0 }); // Entry 682
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 480, minor_id = 90, fade_id = 16, align = 0 }); // Entry 683
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 480, minor_id = 100, fade_id = 16, align = 0 }); // Entry 684
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 480, minor_id = 110, fade_id = 16, align = 0 }); // Entry 685
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 480, minor_id = 120, fade_id = 16, align = 0 }); // Entry 686
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 480, minor_id = 125, fade_id = 2, align = 0 }); // Entry 687
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 480, minor_id = 130, fade_id = 16, align = 0 }); // Entry 688
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 480, minor_id = 140, fade_id = 16, align = 0 }); // Entry 689
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 480, minor_id = 150, fade_id = 16, align = 0 }); // Entry 690
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 480, minor_id = 160, fade_id = 16, align = 0 }); // Entry 691
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 480, minor_id = 165, fade_id = 16, align = 0 }); // Entry 692
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 480, minor_id = 170, fade_id = 16, align = 0 }); // Entry 693
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 481, minor_id = 5, fade_id = 2, align = 0 }); // Entry 694
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 481, minor_id = 10, fade_id = 16, align = 0 }); // Entry 695
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 481, minor_id = 20, fade_id = 16, align = 0 }); // Entry 696
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 481, minor_id = 25, fade_id = 16, align = 0 }); // Entry 697
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 481, minor_id = 30, fade_id = 16, align = 0 }); // Entry 698
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 481, minor_id = 40, fade_id = 16, align = 0 }); // Entry 699
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 481, minor_id = 45, fade_id = 16, align = 0 }); // Entry 700
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 481, minor_id = 50, fade_id = 16, align = 0 }); // Entry 701
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 481, minor_id = 60, fade_id = 16, align = 0 }); // Entry 702
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 481, minor_id = 70, fade_id = 16, align = 0 }); // Entry 703
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 481, minor_id = 80, fade_id = 16, align = 0 }); // Entry 704
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 481, minor_id = 90, fade_id = 16, align = 0 }); // Entry 705
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 481, minor_id = 95, fade_id = 16, align = 0 }); // Entry 706
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 481, minor_id = 100, fade_id = 16, align = 0 }); // Entry 707
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 481, minor_id = 110, fade_id = 16, align = 0 }); // Entry 708
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 481, minor_id = 120, fade_id = 16, align = 0 }); // Entry 709
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 481, minor_id = 130, fade_id = 16, align = 0 }); // Entry 710
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 481, minor_id = 140, fade_id = 16, align = 0 }); // Entry 711
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 482, minor_id = 2, fade_id = 8, align = 0 }); // Entry 712
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 482, minor_id = 3, fade_id = 8, align = 0 }); // Entry 713
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 482, minor_id = 7, fade_id = 8, align = 0 }); // Entry 714
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 482, minor_id = 20, fade_id = 11, align = 0 }); // Entry 715
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 482, minor_id = 30, fade_id = 2, align = 0 }); // Entry 716
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 482, minor_id = 40, fade_id = 2, align = 0 }); // Entry 717
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 483, minor_id = 20, fade_id = 16, align = 0 }); // Entry 718
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 483, minor_id = 30, fade_id = 8, align = 0 }); // Entry 719
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 483, minor_id = 70, fade_id = 1, align = 0 }); // Entry 720
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 483, minor_id = 80, fade_id = 29, align = 0 }); // Entry 721
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 483, minor_id = 90, fade_id = 8, align = 0 }); // Entry 722
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 483, minor_id = 91, fade_id = 29, align = 0 }); // Entry 723
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 483, minor_id = 100, fade_id = 16, align = 0 }); // Entry 724
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 483, minor_id = 110, fade_id = 16, align = 0 }); // Entry 725
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 484, minor_id = 45, fade_id = 16, align = 0 }); // Entry 726
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 484, minor_id = 53, fade_id = 16, align = 0 }); // Entry 727
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 484, minor_id = 55, fade_id = 16, align = 0 }); // Entry 728
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 484, minor_id = 57, fade_id = 16, align = 0 }); // Entry 729
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 484, minor_id = 60, fade_id = 1, align = 0 }); // Entry 730
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 484, minor_id = 70, fade_id = 16, align = 0 }); // Entry 731
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 484, minor_id = 90, fade_id = 1, align = 0 }); // Entry 732
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 484, minor_id = 120, fade_id = 23, align = 0 }); // Entry 733
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 484, minor_id = 140, fade_id = 1, align = 0 }); // Entry 734
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 485, minor_id = 30, fade_id = 2, align = 0 }); // Entry 735
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 485, minor_id = 35, fade_id = 2, align = 0 }); // Entry 736
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 485, minor_id = 40, fade_id = 20, align = 0 }); // Entry 737
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 485, minor_id = 65, fade_id = 2, align = 0 }); // Entry 738
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 485, minor_id = 70, fade_id = 16, align = 0 }); // Entry 739
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 485, minor_id = 80, fade_id = 16, align = 0 }); // Entry 740
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 485, minor_id = 120, fade_id = 16, align = 0 }); // Entry 741
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 485, minor_id = 130, fade_id = 1, align = 0 }); // Entry 742
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 485, minor_id = 135, fade_id = 16, align = 0 }); // Entry 743
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 485, minor_id = 150, fade_id = 16, align = 0 }); // Entry 744
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 485, minor_id = 160, fade_id = 16, align = 0 }); // Entry 745
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 485, minor_id = 210, fade_id = 1, align = 0 }); // Entry 746
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 485, minor_id = 220, fade_id = 16, align = 0 }); // Entry 747
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 485, minor_id = 280, fade_id = 16, align = 0 }); // Entry 748
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 485, minor_id = 285, fade_id = 16, align = 0 }); // Entry 749
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 485, minor_id = 290, fade_id = 16, align = 0 }); // Entry 750
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 485, minor_id = 310, fade_id = 16, align = 0 }); // Entry 751
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 485, minor_id = 330, fade_id = 17, align = 0 }); // Entry 752
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 485, minor_id = 335, fade_id = 1, align = 0 }); // Entry 753
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 485, minor_id = 340, fade_id = 2, align = 0 }); // Entry 754
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 489, minor_id = 30, fade_id = 16, align = 0 }); // Entry 755
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 489, minor_id = 40, fade_id = 16, align = 0 }); // Entry 756
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 489, minor_id = 60, fade_id = 16, align = 0 }); // Entry 757
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 489, minor_id = 90, fade_id = 16, align = 0 }); // Entry 758
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 489, minor_id = 100, fade_id = 16, align = 0 }); // Entry 759
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 497, minor_id = 10, fade_id = 16, align = 0 }); // Entry 760
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 497, minor_id = 15, fade_id = 16, align = 0 }); // Entry 761
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 497, minor_id = 20, fade_id = 16, align = 0 }); // Entry 762
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 497, minor_id = 25, fade_id = 16, align = 0 }); // Entry 763
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 497, minor_id = 30, fade_id = 16, align = 0 }); // Entry 764
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 497, minor_id = 35, fade_id = 16, align = 0 }); // Entry 765
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 497, minor_id = 40, fade_id = 16, align = 0 }); // Entry 766
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 497, minor_id = 43, fade_id = 16, align = 0 }); // Entry 767
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 497, minor_id = 45, fade_id = 16, align = 0 }); // Entry 768
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 499, minor_id = 10, fade_id = 16, align = 0 }); // Entry 769
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 499, minor_id = 20, fade_id = 16, align = 0 }); // Entry 770
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 499, minor_id = 100, fade_id = 16, align = 0 }); // Entry 771
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 499, minor_id = 110, fade_id = 16, align = 0 }); // Entry 772
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 501, minor_id = 10, fade_id = 16, align = 0 }); // Entry 773
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 501, minor_id = 40, fade_id = 16, align = 0 }); // Entry 774
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 501, minor_id = 45, fade_id = 16, align = 0 }); // Entry 775
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 510, minor_id = 10, fade_id = 1, align = 0 }); // Entry 776
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 510, minor_id = 30, fade_id = 1, align = 0 }); // Entry 777
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 510, minor_id = 40, fade_id = 16, align = 0 }); // Entry 778
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 510, minor_id = 50, fade_id = 1, align = 0 }); // Entry 779
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 10, fade_id = 16, align = 0 }); // Entry 780
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 20, fade_id = 8, align = 0 }); // Entry 781
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 30, fade_id = 16, align = 0 }); // Entry 782
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 40, fade_id = 8, align = 0 }); // Entry 783
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 50, fade_id = 1, align = 0 }); // Entry 784
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 60, fade_id = 16, align = 0 }); // Entry 785
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 70, fade_id = 16, align = 0 }); // Entry 786
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 80, fade_id = 8, align = 0 }); // Entry 787
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 90, fade_id = 23, align = 0 }); // Entry 788
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 100, fade_id = 16, align = 0 }); // Entry 789
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 120, fade_id = 16, align = 0 }); // Entry 790
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 130, fade_id = 16, align = 0 }); // Entry 791
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 135, fade_id = 16, align = 0 }); // Entry 792
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 140, fade_id = 16, align = 0 }); // Entry 793
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 145, fade_id = 16, align = 0 }); // Entry 794
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 148, fade_id = 16, align = 0 }); // Entry 795
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 150, fade_id = 16, align = 0 }); // Entry 796
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 170, fade_id = 1, align = 0 }); // Entry 797
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 210, fade_id = 1, align = 0 }); // Entry 798
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 230, fade_id = 23, align = 0 }); // Entry 799
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 240, fade_id = 8, align = 0 }); // Entry 800
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 250, fade_id = 1, align = 0 }); // Entry 801
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 255, fade_id = 16, align = 0 }); // Entry 802
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 260, fade_id = 8, align = 0 }); // Entry 803
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 270, fade_id = 8, align = 0 }); // Entry 804
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 280, fade_id = 8, align = 0 }); // Entry 805
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 290, fade_id = 8, align = 0 }); // Entry 806
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 300, fade_id = 8, align = 0 }); // Entry 807
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 310, fade_id = 8, align = 0 }); // Entry 808
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 315, fade_id = 1, align = 0 }); // Entry 809
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 320, fade_id = 1, align = 0 }); // Entry 810
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 330, fade_id = 16, align = 0 }); // Entry 811
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 345, fade_id = 16, align = 0 }); // Entry 812
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 390, fade_id = 16, align = 0 }); // Entry 813
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 410, fade_id = 23, align = 0 }); // Entry 814
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 420, fade_id = 1, align = 0 }); // Entry 815
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 430, fade_id = 8, align = 0 }); // Entry 816
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 440, fade_id = 16, align = 0 }); // Entry 817
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 442, fade_id = 16, align = 0 }); // Entry 818
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 445, fade_id = 16, align = 0 }); // Entry 819
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 450, fade_id = 16, align = 0 }); // Entry 820
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 460, fade_id = 16, align = 0 }); // Entry 821
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 470, fade_id = 16, align = 0 }); // Entry 822
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 480, fade_id = 16, align = 0 }); // Entry 823
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 520, fade_id = 16, align = 0 }); // Entry 824
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 530, fade_id = 8, align = 0 }); // Entry 825
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 540, fade_id = 1, align = 0 }); // Entry 826
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 550, fade_id = 16, align = 0 }); // Entry 827
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 552, fade_id = 1, align = 0 }); // Entry 828
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 553, fade_id = 1, align = 0 }); // Entry 829
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 557, fade_id = 16, align = 0 }); // Entry 830
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 559, fade_id = 16, align = 0 }); // Entry 831
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 560, fade_id = 16, align = 0 }); // Entry 832
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 562, fade_id = 1, align = 0 }); // Entry 833
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 563, fade_id = 1, align = 0 }); // Entry 834
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 565, fade_id = 23, align = 0 }); // Entry 835
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 566, fade_id = 16, align = 0 }); // Entry 836
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 567, fade_id = 1, align = 0 }); // Entry 837
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 568, fade_id = 1, align = 0 }); // Entry 838
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 569, fade_id = 1, align = 0 }); // Entry 839
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 590, fade_id = 1, align = 0 }); // Entry 840
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 593, fade_id = 1, align = 0 }); // Entry 841
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 595, fade_id = 1, align = 0 }); // Entry 842
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 604, fade_id = 1, align = 0 }); // Entry 843
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 605, fade_id = 1, align = 0 }); // Entry 844
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 625, fade_id = 1, align = 0 }); // Entry 845
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 511, minor_id = 630, fade_id = 16, align = 0 }); // Entry 846
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 512, minor_id = 10, fade_id = 16, align = 0 }); // Entry 847
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 512, minor_id = 30, fade_id = 16, align = 0 }); // Entry 848
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 512, minor_id = 40, fade_id = 16, align = 0 }); // Entry 849
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 512, minor_id = 50, fade_id = 16, align = 0 }); // Entry 850
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 512, minor_id = 85, fade_id = 16, align = 0 }); // Entry 851
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 512, minor_id = 110, fade_id = 16, align = 0 }); // Entry 852
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 521, minor_id = 10, fade_id = 8, align = 0 }); // Entry 853
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 521, minor_id = 12, fade_id = 16, align = 0 }); // Entry 854
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 521, minor_id = 13, fade_id = 1, align = 0 }); // Entry 855
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 521, minor_id = 15, fade_id = 1, align = 0 }); // Entry 856
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 521, minor_id = 17, fade_id = 1, align = 0 }); // Entry 857
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 521, minor_id = 18, fade_id = 16, align = 0 }); // Entry 858
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 521, minor_id = 19, fade_id = 1, align = 0 }); // Entry 859
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 521, minor_id = 21, fade_id = 16, align = 0 }); // Entry 860
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 521, minor_id = 25, fade_id = 16, align = 0 }); // Entry 861
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 522, minor_id = 20, fade_id = 16, align = 0 }); // Entry 862
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 522, minor_id = 30, fade_id = 1, align = 0 }); // Entry 863
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 522, minor_id = 60, fade_id = 1, align = 0 }); // Entry 864
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 616, minor_id = 10, fade_id = 16, align = 0 }); // Entry 865
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 695, minor_id = 1, fade_id = 8, align = 0 }); // Entry 866
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 695, minor_id = 11, fade_id = 8, align = 0 }); // Entry 867
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 696, minor_id = 1, fade_id = 8, align = 0 }); // Entry 868
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 697, minor_id = 1, fade_id = 8, align = 0 }); // Entry 869
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 697, minor_id = 11, fade_id = 8, align = 0 }); // Entry 870
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 698, minor_id = 1, fade_id = 16, align = 0 }); // Entry 871
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 698, minor_id = 2, fade_id = 16, align = 0 }); // Entry 872
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 698, minor_id = 3, fade_id = 16, align = 0 }); // Entry 873
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 698, minor_id = 4, fade_id = 16, align = 0 }); // Entry 874
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 699, minor_id = 1, fade_id = 8, align = 0 }); // Entry 875
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 700, minor_id = 300, fade_id = 1, align = 0 }); // Entry 876
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 700, minor_id = 301, fade_id = 1, align = 0 }); // Entry 877
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 701, minor_id = 200, fade_id = 1, align = 0 }); // Entry 878
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 702, minor_id = 10, fade_id = 8, align = 0 }); // Entry 879
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 702, minor_id = 11, fade_id = 2, align = 0 }); // Entry 880
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 702, minor_id = 20, fade_id = 8, align = 0 }); // Entry 881
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 702, minor_id = 30, fade_id = 8, align = 0 }); // Entry 882
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 702, minor_id = 40, fade_id = 8, align = 0 }); // Entry 883
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 702, minor_id = 50, fade_id = 8, align = 0 }); // Entry 884
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 702, minor_id = 60, fade_id = 8, align = 0 }); // Entry 885
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 702, minor_id = 70, fade_id = 8, align = 0 }); // Entry 886
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 702, minor_id = 80, fade_id = 8, align = 0 }); // Entry 887
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 702, minor_id = 91, fade_id = 2, align = 0 }); // Entry 888
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 702, minor_id = 92, fade_id = 8, align = 0 }); // Entry 889
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 702, minor_id = 100, fade_id = 8, align = 0 }); // Entry 890
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 702, minor_id = 101, fade_id = 16, align = 0 }); // Entry 891
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 702, minor_id = 205, fade_id = 16, align = 0 }); // Entry 892
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 702, minor_id = 300, fade_id = 8, align = 0 }); // Entry 893
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 703, minor_id = 10, fade_id = 8, align = 0 }); // Entry 894
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 703, minor_id = 11, fade_id = 16, align = 0 }); // Entry 895
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 703, minor_id = 20, fade_id = 8, align = 0 }); // Entry 896
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 703, minor_id = 30, fade_id = 8, align = 0 }); // Entry 897
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 703, minor_id = 40, fade_id = 8, align = 0 }); // Entry 898
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 703, minor_id = 50, fade_id = 8, align = 0 }); // Entry 899
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 703, minor_id = 60, fade_id = 8, align = 0 }); // Entry 900
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 703, minor_id = 70, fade_id = 8, align = 0 }); // Entry 901
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 703, minor_id = 80, fade_id = 8, align = 0 }); // Entry 902
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 703, minor_id = 90, fade_id = 8, align = 0 }); // Entry 903
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 703, minor_id = 100, fade_id = 16, align = 0 }); // Entry 904
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 703, minor_id = 101, fade_id = 16, align = 0 }); // Entry 905
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 703, minor_id = 205, fade_id = 8, align = 0 }); // Entry 906
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 703, minor_id = 300, fade_id = 16, align = 0 }); // Entry 907
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 704, minor_id = 10, fade_id = 16, align = 0 }); // Entry 908
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 704, minor_id = 12, fade_id = 8, align = 0 }); // Entry 909
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 704, minor_id = 13, fade_id = 23, align = 0 }); // Entry 910
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 704, minor_id = 20, fade_id = 16, align = 0 }); // Entry 911
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 704, minor_id = 30, fade_id = 8, align = 0 }); // Entry 912
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 704, minor_id = 40, fade_id = 8, align = 0 }); // Entry 913
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 704, minor_id = 50, fade_id = 8, align = 0 }); // Entry 914
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 704, minor_id = 60, fade_id = 16, align = 0 }); // Entry 915
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 704, minor_id = 61, fade_id = 16, align = 0 }); // Entry 916
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 704, minor_id = 62, fade_id = 8, align = 0 }); // Entry 917
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 704, minor_id = 71, fade_id = 8, align = 0 }); // Entry 918
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 704, minor_id = 80, fade_id = 16, align = 0 }); // Entry 919
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 704, minor_id = 90, fade_id = 23, align = 0 }); // Entry 920
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 704, minor_id = 91, fade_id = 8, align = 0 }); // Entry 921
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 704, minor_id = 100, fade_id = 8, align = 0 }); // Entry 922
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 704, minor_id = 205, fade_id = 8, align = 0 }); // Entry 923
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 704, minor_id = 300, fade_id = 8, align = 0 }); // Entry 924
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 705, minor_id = 10, fade_id = 16, align = 0 }); // Entry 925
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 705, minor_id = 20, fade_id = 1, align = 0 }); // Entry 926
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 705, minor_id = 30, fade_id = 1, align = 0 }); // Entry 927
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 705, minor_id = 40, fade_id = 1, align = 0 }); // Entry 928
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 705, minor_id = 50, fade_id = 1, align = 0 }); // Entry 929
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 705, minor_id = 60, fade_id = 1, align = 0 }); // Entry 930
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 705, minor_id = 70, fade_id = 1, align = 0 }); // Entry 931
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 705, minor_id = 80, fade_id = 1, align = 0 }); // Entry 932
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 705, minor_id = 81, fade_id = 1, align = 0 }); // Entry 933
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 705, minor_id = 90, fade_id = 1, align = 0 }); // Entry 934
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 705, minor_id = 101, fade_id = 1, align = 0 }); // Entry 935
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 705, minor_id = 300, fade_id = 1, align = 0 }); // Entry 936
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 706, minor_id = 20, fade_id = 8, align = 0 }); // Entry 937
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 706, minor_id = 30, fade_id = 8, align = 0 }); // Entry 938
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 706, minor_id = 40, fade_id = 8, align = 0 }); // Entry 939
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 706, minor_id = 50, fade_id = 2, align = 0 }); // Entry 940
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 706, minor_id = 51, fade_id = 8, align = 0 }); // Entry 941
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 706, minor_id = 60, fade_id = 8, align = 0 }); // Entry 942
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 706, minor_id = 70, fade_id = 8, align = 0 }); // Entry 943
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 706, minor_id = 71, fade_id = 8, align = 0 }); // Entry 944
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 706, minor_id = 72, fade_id = 8, align = 0 }); // Entry 945
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 706, minor_id = 80, fade_id = 8, align = 0 }); // Entry 946
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 706, minor_id = 90, fade_id = 8, align = 0 }); // Entry 947
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 706, minor_id = 100, fade_id = 8, align = 0 }); // Entry 948
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 706, minor_id = 102, fade_id = 8, align = 0 }); // Entry 949
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 706, minor_id = 103, fade_id = 8, align = 0 }); // Entry 950
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 706, minor_id = 205, fade_id = 16, align = 0 }); // Entry 951
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 707, minor_id = 20, fade_id = 8, align = 0 }); // Entry 952
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 707, minor_id = 30, fade_id = 8, align = 0 }); // Entry 953
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 707, minor_id = 41, fade_id = 8, align = 0 }); // Entry 954
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 707, minor_id = 50, fade_id = 8, align = 0 }); // Entry 955
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 707, minor_id = 51, fade_id = 16, align = 0 }); // Entry 956
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 707, minor_id = 60, fade_id = 8, align = 0 }); // Entry 957
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 707, minor_id = 70, fade_id = 8, align = 0 }); // Entry 958
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 707, minor_id = 81, fade_id = 8, align = 0 }); // Entry 959
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 707, minor_id = 90, fade_id = 8, align = 0 }); // Entry 960
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 707, minor_id = 100, fade_id = 8, align = 0 }); // Entry 961
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 707, minor_id = 205, fade_id = 16, align = 0 }); // Entry 962
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 709, minor_id = 10, fade_id = 8, align = 0 }); // Entry 963
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 709, minor_id = 11, fade_id = 16, align = 0 }); // Entry 964
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 709, minor_id = 20, fade_id = 16, align = 0 }); // Entry 965
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 709, minor_id = 30, fade_id = 8, align = 0 }); // Entry 966
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 709, minor_id = 31, fade_id = 8, align = 0 }); // Entry 967
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 709, minor_id = 40, fade_id = 8, align = 0 }); // Entry 968
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 709, minor_id = 41, fade_id = 8, align = 0 }); // Entry 969
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 709, minor_id = 50, fade_id = 8, align = 0 }); // Entry 970
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 709, minor_id = 51, fade_id = 8, align = 0 }); // Entry 971
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 709, minor_id = 60, fade_id = 2, align = 0 }); // Entry 972
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 709, minor_id = 70, fade_id = 2, align = 0 }); // Entry 973
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 709, minor_id = 80, fade_id = 16, align = 0 }); // Entry 974
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 709, minor_id = 90, fade_id = 16, align = 0 }); // Entry 975
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 709, minor_id = 100, fade_id = 8, align = 0 }); // Entry 976
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 709, minor_id = 101, fade_id = 2, align = 0 }); // Entry 977
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 709, minor_id = 205, fade_id = 16, align = 0 }); // Entry 978
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 710, minor_id = 0, fade_id = 8, align = 0 }); // Entry 979
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 710, minor_id = 1, fade_id = 1, align = 0 }); // Entry 980
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 710, minor_id = 10, fade_id = 1, align = 0 }); // Entry 981
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 710, minor_id = 11, fade_id = 16, align = 0 }); // Entry 982
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 710, minor_id = 12, fade_id = 1, align = 0 }); // Entry 983
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 710, minor_id = 20, fade_id = 1, align = 0 }); // Entry 984
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 710, minor_id = 30, fade_id = 1, align = 0 }); // Entry 985
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 710, minor_id = 40, fade_id = 1, align = 0 }); // Entry 986
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 710, minor_id = 50, fade_id = 1, align = 0 }); // Entry 987
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 710, minor_id = 60, fade_id = 1, align = 0 }); // Entry 988
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 710, minor_id = 70, fade_id = 1, align = 0 }); // Entry 989
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 710, minor_id = 80, fade_id = 1, align = 0 }); // Entry 990
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 710, minor_id = 81, fade_id = 1, align = 0 }); // Entry 991
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 710, minor_id = 90, fade_id = 1, align = 0 }); // Entry 992
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 710, minor_id = 100, fade_id = 1, align = 0 }); // Entry 993
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 710, minor_id = 101, fade_id = 1, align = 0 }); // Entry 994
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 710, minor_id = 200, fade_id = 8, align = 0 }); // Entry 995
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 710, minor_id = 201, fade_id = 8, align = 0 }); // Entry 996
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 710, minor_id = 300, fade_id = 1, align = 0 }); // Entry 997
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 711, minor_id = 10, fade_id = 16, align = 0 }); // Entry 998
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 711, minor_id = 20, fade_id = 16, align = 0 }); // Entry 999
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 711, minor_id = 30, fade_id = 16, align = 0 }); // Entry 1000
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 711, minor_id = 40, fade_id = 16, align = 0 }); // Entry 1001
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 711, minor_id = 50, fade_id = 16, align = 0 }); // Entry 1002
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 711, minor_id = 60, fade_id = 16, align = 0 }); // Entry 1003
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 711, minor_id = 70, fade_id = 16, align = 0 }); // Entry 1004
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 711, minor_id = 80, fade_id = 16, align = 0 }); // Entry 1005
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 711, minor_id = 90, fade_id = 16, align = 0 }); // Entry 1006
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 711, minor_id = 100, fade_id = 16, align = 0 }); // Entry 1007
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 712, minor_id = 0, fade_id = 1, align = 0 }); // Entry 1008
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 712, minor_id = 1, fade_id = 16, align = 0 }); // Entry 1009
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 712, minor_id = 10, fade_id = 2, align = 0 }); // Entry 1010
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 712, minor_id = 11, fade_id = 1, align = 0 }); // Entry 1011
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 712, minor_id = 12, fade_id = 16, align = 0 }); // Entry 1012
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 712, minor_id = 13, fade_id = 8, align = 0 }); // Entry 1013
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 712, minor_id = 20, fade_id = 1, align = 0 }); // Entry 1014
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 712, minor_id = 30, fade_id = 1, align = 0 }); // Entry 1015
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 712, minor_id = 40, fade_id = 16, align = 0 }); // Entry 1016
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 712, minor_id = 41, fade_id = 1, align = 0 }); // Entry 1017
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 712, minor_id = 50, fade_id = 1, align = 0 }); // Entry 1018
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 712, minor_id = 60, fade_id = 1, align = 0 }); // Entry 1019
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 712, minor_id = 70, fade_id = 1, align = 0 }); // Entry 1020
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 712, minor_id = 80, fade_id = 1, align = 0 }); // Entry 1021
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 712, minor_id = 81, fade_id = 1, align = 0 }); // Entry 1022
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 712, minor_id = 90, fade_id = 8, align = 0 }); // Entry 1023
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 712, minor_id = 91, fade_id = 1, align = 0 }); // Entry 1024
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 712, minor_id = 100, fade_id = 1, align = 0 }); // Entry 1025
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 712, minor_id = 200, fade_id = 8, align = 0 }); // Entry 1026
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 712, minor_id = 202, fade_id = 8, align = 0 }); // Entry 1027
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 712, minor_id = 300, fade_id = 1, align = 0 }); // Entry 1028
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 713, minor_id = 0, fade_id = 1, align = 0 }); // Entry 1029
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 713, minor_id = 10, fade_id = 2, align = 0 }); // Entry 1030
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 713, minor_id = 11, fade_id = 1, align = 0 }); // Entry 1031
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 713, minor_id = 12, fade_id = 16, align = 0 }); // Entry 1032
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 713, minor_id = 13, fade_id = 1, align = 0 }); // Entry 1033
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 713, minor_id = 20, fade_id = 2, align = 0 }); // Entry 1034
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 713, minor_id = 30, fade_id = 2, align = 0 }); // Entry 1035
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 713, minor_id = 40, fade_id = 2, align = 0 }); // Entry 1036
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 713, minor_id = 50, fade_id = 2, align = 0 }); // Entry 1037
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 713, minor_id = 60, fade_id = 2, align = 0 }); // Entry 1038
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 713, minor_id = 70, fade_id = 29, align = 0 }); // Entry 1039
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 713, minor_id = 80, fade_id = 29, align = 0 }); // Entry 1040
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 713, minor_id = 81, fade_id = 2, align = 0 }); // Entry 1041
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 713, minor_id = 90, fade_id = 8, align = 0 }); // Entry 1042
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 713, minor_id = 100, fade_id = 1, align = 0 }); // Entry 1043
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 713, minor_id = 101, fade_id = 1, align = 0 }); // Entry 1044
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 713, minor_id = 200, fade_id = 2, align = 0 }); // Entry 1045
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 713, minor_id = 201, fade_id = 2, align = 0 }); // Entry 1046
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 713, minor_id = 300, fade_id = 1, align = 0 }); // Entry 1047
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 714, minor_id = 10, fade_id = 16, align = 0 }); // Entry 1048
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 714, minor_id = 11, fade_id = 1, align = 0 }); // Entry 1049
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 714, minor_id = 12, fade_id = 16, align = 0 }); // Entry 1050
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 714, minor_id = 20, fade_id = 1, align = 0 }); // Entry 1051
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 714, minor_id = 30, fade_id = 1, align = 0 }); // Entry 1052
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 714, minor_id = 40, fade_id = 1, align = 0 }); // Entry 1053
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 714, minor_id = 50, fade_id = 1, align = 0 }); // Entry 1054
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 714, minor_id = 60, fade_id = 1, align = 0 }); // Entry 1055
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 714, minor_id = 70, fade_id = 1, align = 0 }); // Entry 1056
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 714, minor_id = 80, fade_id = 1, align = 0 }); // Entry 1057
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 714, minor_id = 90, fade_id = 16, align = 0 }); // Entry 1058
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 714, minor_id = 91, fade_id = 1, align = 0 }); // Entry 1059
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 714, minor_id = 92, fade_id = 16, align = 0 }); // Entry 1060
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 714, minor_id = 100, fade_id = 16, align = 0 }); // Entry 1061
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 714, minor_id = 101, fade_id = 1, align = 0 }); // Entry 1062
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 714, minor_id = 102, fade_id = 1, align = 0 }); // Entry 1063
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 714, minor_id = 200, fade_id = 16, align = 0 }); // Entry 1064
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 714, minor_id = 201, fade_id = 16, align = 0 }); // Entry 1065
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 714, minor_id = 300, fade_id = 1, align = 0 }); // Entry 1066
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 715, minor_id = 10, fade_id = 16, align = 0 }); // Entry 1067
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 715, minor_id = 20, fade_id = 1, align = 0 }); // Entry 1068
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 715, minor_id = 30, fade_id = 1, align = 0 }); // Entry 1069
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 715, minor_id = 40, fade_id = 1, align = 0 }); // Entry 1070
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 715, minor_id = 50, fade_id = 1, align = 0 }); // Entry 1071
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 715, minor_id = 60, fade_id = 1, align = 0 }); // Entry 1072
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 715, minor_id = 70, fade_id = 1, align = 0 }); // Entry 1073
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 715, minor_id = 80, fade_id = 1, align = 0 }); // Entry 1074
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 715, minor_id = 81, fade_id = 1, align = 0 }); // Entry 1075
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 715, minor_id = 90, fade_id = 1, align = 0 }); // Entry 1076
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 715, minor_id = 100, fade_id = 1, align = 0 }); // Entry 1077
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 715, minor_id = 101, fade_id = 1, align = 0 }); // Entry 1078
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 715, minor_id = 200, fade_id = 8, align = 0 }); // Entry 1079
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 715, minor_id = 201, fade_id = 8, align = 0 }); // Entry 1080
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 715, minor_id = 300, fade_id = 1, align = 0 }); // Entry 1081
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 716, minor_id = 10, fade_id = 8, align = 0 }); // Entry 1082
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 716, minor_id = 11, fade_id = 2, align = 0 }); // Entry 1083
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 716, minor_id = 20, fade_id = 8, align = 0 }); // Entry 1084
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 716, minor_id = 30, fade_id = 8, align = 0 }); // Entry 1085
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 716, minor_id = 40, fade_id = 8, align = 0 }); // Entry 1086
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 716, minor_id = 50, fade_id = 8, align = 0 }); // Entry 1087
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 716, minor_id = 60, fade_id = 8, align = 0 }); // Entry 1088
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 716, minor_id = 70, fade_id = 8, align = 0 }); // Entry 1089
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 716, minor_id = 80, fade_id = 8, align = 0 }); // Entry 1090
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 716, minor_id = 91, fade_id = 8, align = 0 }); // Entry 1091
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 716, minor_id = 100, fade_id = 8, align = 0 }); // Entry 1092
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 716, minor_id = 200, fade_id = 8, align = 0 }); // Entry 1093
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 716, minor_id = 201, fade_id = 8, align = 0 }); // Entry 1094
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 716, minor_id = 300, fade_id = 8, align = 0 }); // Entry 1095
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 717, minor_id = 1, fade_id = 8, align = 0 }); // Entry 1096
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 717, minor_id = 11, fade_id = 1, align = 0 }); // Entry 1097
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 717, minor_id = 20, fade_id = 1, align = 0 }); // Entry 1098
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 717, minor_id = 30, fade_id = 1, align = 0 }); // Entry 1099
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 717, minor_id = 40, fade_id = 1, align = 0 }); // Entry 1100
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 717, minor_id = 50, fade_id = 1, align = 0 }); // Entry 1101
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 717, minor_id = 60, fade_id = 1, align = 0 }); // Entry 1102
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 717, minor_id = 70, fade_id = 1, align = 0 }); // Entry 1103
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 717, minor_id = 80, fade_id = 1, align = 0 }); // Entry 1104
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 717, minor_id = 81, fade_id = 1, align = 0 }); // Entry 1105
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 717, minor_id = 91, fade_id = 1, align = 0 }); // Entry 1106
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 717, minor_id = 100, fade_id = 1, align = 0 }); // Entry 1107
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 717, minor_id = 101, fade_id = 1, align = 0 }); // Entry 1108
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 717, minor_id = 200, fade_id = 8, align = 0 }); // Entry 1109
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 717, minor_id = 201, fade_id = 8, align = 0 }); // Entry 1110
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 717, minor_id = 300, fade_id = 1, align = 0 }); // Entry 1111
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 718, minor_id = 10, fade_id = 8, align = 0 }); // Entry 1112
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 718, minor_id = 20, fade_id = 2, align = 0 }); // Entry 1113
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 718, minor_id = 30, fade_id = 1, align = 0 }); // Entry 1114
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 718, minor_id = 40, fade_id = 1, align = 0 }); // Entry 1115
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 718, minor_id = 50, fade_id = 1, align = 0 }); // Entry 1116
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 718, minor_id = 60, fade_id = 1, align = 0 }); // Entry 1117
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 718, minor_id = 61, fade_id = 8, align = 0 }); // Entry 1118
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 718, minor_id = 62, fade_id = 8, align = 0 }); // Entry 1119
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 718, minor_id = 70, fade_id = 1, align = 0 }); // Entry 1120
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 718, minor_id = 71, fade_id = 1, align = 0 }); // Entry 1121
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 718, minor_id = 72, fade_id = 1, align = 0 }); // Entry 1122
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 718, minor_id = 80, fade_id = 1, align = 0 }); // Entry 1123
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 718, minor_id = 90, fade_id = 1, align = 0 }); // Entry 1124
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 718, minor_id = 100, fade_id = 1, align = 0 }); // Entry 1125
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 719, minor_id = 1, fade_id = 1, align = 0 }); // Entry 1126
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 719, minor_id = 11, fade_id = 1, align = 0 }); // Entry 1127
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 719, minor_id = 20, fade_id = 1, align = 0 }); // Entry 1128
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 719, minor_id = 30, fade_id = 1, align = 0 }); // Entry 1129
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 719, minor_id = 40, fade_id = 1, align = 0 }); // Entry 1130
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 719, minor_id = 50, fade_id = 1, align = 0 }); // Entry 1131
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 719, minor_id = 60, fade_id = 1, align = 0 }); // Entry 1132
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 719, minor_id = 70, fade_id = 1, align = 0 }); // Entry 1133
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 719, minor_id = 80, fade_id = 1, align = 0 }); // Entry 1134
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 719, minor_id = 90, fade_id = 1, align = 0 }); // Entry 1135
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 719, minor_id = 100, fade_id = 1, align = 0 }); // Entry 1136
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 719, minor_id = 200, fade_id = 8, align = 0 }); // Entry 1137
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 719, minor_id = 201, fade_id = 8, align = 0 }); // Entry 1138
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 719, minor_id = 300, fade_id = 1, align = 0 }); // Entry 1139
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 722, minor_id = 10, fade_id = 8, align = 0 }); // Entry 1140
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 722, minor_id = 20, fade_id = 2, align = 0 }); // Entry 1141
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 722, minor_id = 30, fade_id = 8, align = 0 }); // Entry 1142
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 722, minor_id = 31, fade_id = 8, align = 0 }); // Entry 1143
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 722, minor_id = 40, fade_id = 8, align = 0 }); // Entry 1144
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 722, minor_id = 50, fade_id = 8, align = 0 }); // Entry 1145
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 722, minor_id = 60, fade_id = 8, align = 0 }); // Entry 1146
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 722, minor_id = 70, fade_id = 8, align = 0 }); // Entry 1147
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 722, minor_id = 80, fade_id = 8, align = 0 }); // Entry 1148
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 722, minor_id = 90, fade_id = 8, align = 0 }); // Entry 1149
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 722, minor_id = 100, fade_id = 8, align = 0 }); // Entry 1150
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 722, minor_id = 22, fade_id = 8, align = 0 }); // Entry 1151
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 722, minor_id = 32, fade_id = 8, align = 0 }); // Entry 1152
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 722, minor_id = 42, fade_id = 8, align = 0 }); // Entry 1153
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 722, minor_id = 52, fade_id = 8, align = 0 }); // Entry 1154
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 722, minor_id = 62, fade_id = 8, align = 0 }); // Entry 1155
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 722, minor_id = 72, fade_id = 8, align = 0 }); // Entry 1156
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 722, minor_id = 82, fade_id = 8, align = 0 }); // Entry 1157
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 722, minor_id = 92, fade_id = 1, align = 0 }); // Entry 1158
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 722, minor_id = 102, fade_id = 1, align = 0 }); // Entry 1159
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 722, minor_id = 103, fade_id = 1, align = 0 }); // Entry 1160
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 723, minor_id = 10, fade_id = 8, align = 0 }); // Entry 1161
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 723, minor_id = 20, fade_id = 8, align = 0 }); // Entry 1162
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 723, minor_id = 30, fade_id = 8, align = 0 }); // Entry 1163
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 723, minor_id = 40, fade_id = 8, align = 0 }); // Entry 1164
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 723, minor_id = 50, fade_id = 8, align = 0 }); // Entry 1165
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 723, minor_id = 60, fade_id = 8, align = 0 }); // Entry 1166
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 723, minor_id = 70, fade_id = 8, align = 0 }); // Entry 1167
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 723, minor_id = 80, fade_id = 8, align = 0 }); // Entry 1168
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 723, minor_id = 90, fade_id = 8, align = 0 }); // Entry 1169
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 723, minor_id = 100, fade_id = 8, align = 0 }); // Entry 1170
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 723, minor_id = 107, fade_id = 16, align = 0 }); // Entry 1171
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 723, minor_id = 101, fade_id = 2, align = 0 }); // Entry 1172
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 723, minor_id = 102, fade_id = 16, align = 0 }); // Entry 1173
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 723, minor_id = 103, fade_id = 16, align = 0 }); // Entry 1174
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 723, minor_id = 22, fade_id = 8, align = 0 }); // Entry 1175
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 723, minor_id = 32, fade_id = 8, align = 0 }); // Entry 1176
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 723, minor_id = 42, fade_id = 8, align = 0 }); // Entry 1177
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 723, minor_id = 52, fade_id = 8, align = 0 }); // Entry 1178
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 723, minor_id = 62, fade_id = 16, align = 0 }); // Entry 1179
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 723, minor_id = 72, fade_id = 8, align = 0 }); // Entry 1180
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 723, minor_id = 82, fade_id = 8, align = 0 }); // Entry 1181
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 723, minor_id = 83, fade_id = 8, align = 0 }); // Entry 1182
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 723, minor_id = 84, fade_id = 8, align = 0 }); // Entry 1183
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 723, minor_id = 86, fade_id = 16, align = 0 }); // Entry 1184
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 723, minor_id = 92, fade_id = 8, align = 0 }); // Entry 1185
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 723, minor_id = 15, fade_id = 1, align = 0 }); // Entry 1186
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 723, minor_id = 25, fade_id = 1, align = 0 }); // Entry 1187
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 723, minor_id = 45, fade_id = 1, align = 0 }); // Entry 1188
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 723, minor_id = 65, fade_id = 1, align = 0 }); // Entry 1189
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 723, minor_id = 75, fade_id = 1, align = 0 }); // Entry 1190
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 723, minor_id = 85, fade_id = 1, align = 0 }); // Entry 1191
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 726, minor_id = 22, fade_id = 1, align = 0 }); // Entry 1192
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 726, minor_id = 32, fade_id = 1, align = 0 }); // Entry 1193
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 726, minor_id = 42, fade_id = 16, align = 0 }); // Entry 1194
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 726, minor_id = 43, fade_id = 1, align = 0 }); // Entry 1195
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 726, minor_id = 52, fade_id = 1, align = 0 }); // Entry 1196
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 726, minor_id = 62, fade_id = 16, align = 0 }); // Entry 1197
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 726, minor_id = 63, fade_id = 1, align = 0 }); // Entry 1198
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 726, minor_id = 72, fade_id = 16, align = 0 }); // Entry 1199
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 726, minor_id = 73, fade_id = 1, align = 0 }); // Entry 1200
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 726, minor_id = 82, fade_id = 1, align = 0 }); // Entry 1201
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 726, minor_id = 83, fade_id = 23, align = 0 }); // Entry 1202
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 726, minor_id = 84, fade_id = 1, align = 0 }); // Entry 1203
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 726, minor_id = 86, fade_id = 1, align = 0 }); // Entry 1204
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 729, minor_id = 11, fade_id = 1, align = 0 }); // Entry 1205
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 729, minor_id = 12, fade_id = 16, align = 0 }); // Entry 1206
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 729, minor_id = 13, fade_id = 1, align = 0 }); // Entry 1207
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 729, minor_id = 20, fade_id = 1, align = 0 }); // Entry 1208
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 729, minor_id = 30, fade_id = 1, align = 0 }); // Entry 1209
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 729, minor_id = 40, fade_id = 1, align = 0 }); // Entry 1210
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 729, minor_id = 50, fade_id = 1, align = 0 }); // Entry 1211
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 729, minor_id = 60, fade_id = 1, align = 0 }); // Entry 1212
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 729, minor_id = 70, fade_id = 1, align = 0 }); // Entry 1213
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 729, minor_id = 80, fade_id = 1, align = 0 }); // Entry 1214
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 729, minor_id = 90, fade_id = 1, align = 0 }); // Entry 1215
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 729, minor_id = 100, fade_id = 1, align = 0 }); // Entry 1216
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 729, minor_id = 200, fade_id = 8, align = 0 }); // Entry 1217
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 729, minor_id = 210, fade_id = 1, align = 0 }); // Entry 1218
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 729, minor_id = 220, fade_id = 1, align = 0 }); // Entry 1219
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 730, minor_id = 1, fade_id = 16, align = 0 }); // Entry 1220
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 731, minor_id = 1, fade_id = 16, align = 0 }); // Entry 1221
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 731, minor_id = 2, fade_id = 16, align = 0 }); // Entry 1222
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 731, minor_id = 12, fade_id = 16, align = 0 }); // Entry 1223
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 732, minor_id = 1, fade_id = 16, align = 0 }); // Entry 1224
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 732, minor_id = 12, fade_id = 16, align = 0 }); // Entry 1225
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 733, minor_id = 1, fade_id = 16, align = 0 }); // Entry 1226
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 736, minor_id = 1, fade_id = 16, align = 0 }); // Entry 1227
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 737, minor_id = 1, fade_id = 1, align = 0 }); // Entry 1228
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 737, minor_id = 2, fade_id = 1, align = 0 }); // Entry 1229
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 737, minor_id = 4, fade_id = 16, align = 0 }); // Entry 1230
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 738, minor_id = 1, fade_id = 1, align = 0 }); // Entry 1231
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 738, minor_id = 2, fade_id = 16, align = 0 }); // Entry 1232
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 738, minor_id = 3, fade_id = 16, align = 0 }); // Entry 1233
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 740, minor_id = 1, fade_id = 8, align = 0 }); // Entry 1234
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 740, minor_id = 11, fade_id = 8, align = 0 }); // Entry 1235
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 740, minor_id = 21, fade_id = 8, align = 0 }); // Entry 1236
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 740, minor_id = 31, fade_id = 8, align = 0 }); // Entry 1237
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 740, minor_id = 41, fade_id = 8, align = 0 }); // Entry 1238
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 740, minor_id = 51, fade_id = 8, align = 0 }); // Entry 1239
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 740, minor_id = 61, fade_id = 8, align = 0 }); // Entry 1240
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 740, minor_id = 71, fade_id = 8, align = 0 }); // Entry 1241
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 740, minor_id = 81, fade_id = 8, align = 0 }); // Entry 1242
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 740, minor_id = 91, fade_id = 8, align = 0 }); // Entry 1243
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 740, minor_id = 101, fade_id = 8, align = 0 }); // Entry 1244
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 740, minor_id = 111, fade_id = 8, align = 0 }); // Entry 1245
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 740, minor_id = 131, fade_id = 8, align = 0 }); // Entry 1246
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 740, minor_id = 141, fade_id = 8, align = 0 }); // Entry 1247
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 747, minor_id = 0, fade_id = 2, align = 0 }); // Entry 1248
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 747, minor_id = 1, fade_id = 2, align = 0 }); // Entry 1249
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 747, minor_id = 2, fade_id = 2, align = 0 }); // Entry 1250
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 747, minor_id = 3, fade_id = 2, align = 0 }); // Entry 1251
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 747, minor_id = 4, fade_id = 2, align = 0 }); // Entry 1252
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 747, minor_id = 101, fade_id = 2, align = 0 }); // Entry 1253
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 748, minor_id = 0, fade_id = 16, align = 0 }); // Entry 1254
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 748, minor_id = 1, fade_id = 8, align = 0 }); // Entry 1255
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 748, minor_id = 10, fade_id = 16, align = 0 }); // Entry 1256
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 748, minor_id = 11, fade_id = 8, align = 0 }); // Entry 1257
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 748, minor_id = 20, fade_id = 16, align = 0 }); // Entry 1258
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 748, minor_id = 21, fade_id = 8, align = 0 }); // Entry 1259
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 748, minor_id = 30, fade_id = 16, align = 0 }); // Entry 1260
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 748, minor_id = 31, fade_id = 8, align = 0 }); // Entry 1261
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 748, minor_id = 40, fade_id = 16, align = 0 }); // Entry 1262
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 748, minor_id = 41, fade_id = 8, align = 0 }); // Entry 1263
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 748, minor_id = 50, fade_id = 8, align = 0 }); // Entry 1264
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 748, minor_id = 101, fade_id = 1, align = 0 }); // Entry 1265
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 748, minor_id = 102, fade_id = 1, align = 0 }); // Entry 1266
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 749, minor_id = 0, fade_id = 1, align = 0 }); // Entry 1267
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 749, minor_id = 1, fade_id = 1, align = 0 }); // Entry 1268
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 749, minor_id = 2, fade_id = 1, align = 0 }); // Entry 1269
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 749, minor_id = 3, fade_id = 1, align = 0 }); // Entry 1270
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 749, minor_id = 4, fade_id = 1, align = 0 }); // Entry 1271
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 749, minor_id = 5, fade_id = 1, align = 0 }); // Entry 1272
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 749, minor_id = 6, fade_id = 1, align = 0 }); // Entry 1273
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 749, minor_id = 7, fade_id = 1, align = 0 }); // Entry 1274
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 749, minor_id = 8, fade_id = 1, align = 0 }); // Entry 1275
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 749, minor_id = 9, fade_id = 1, align = 0 }); // Entry 1276
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 749, minor_id = 101, fade_id = 8, align = 0 }); // Entry 1277
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 750, minor_id = 0, fade_id = 1, align = 0 }); // Entry 1278
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 750, minor_id = 1, fade_id = 1, align = 0 }); // Entry 1279
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 750, minor_id = 2, fade_id = 1, align = 0 }); // Entry 1280
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 750, minor_id = 3, fade_id = 1, align = 0 }); // Entry 1281
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 750, minor_id = 4, fade_id = 1, align = 0 }); // Entry 1282
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 750, minor_id = 5, fade_id = 1, align = 0 }); // Entry 1283
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 750, minor_id = 6, fade_id = 1, align = 0 }); // Entry 1284
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 750, minor_id = 7, fade_id = 1, align = 0 }); // Entry 1285
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 750, minor_id = 8, fade_id = 1, align = 0 }); // Entry 1286
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 750, minor_id = 9, fade_id = 1, align = 0 }); // Entry 1287
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 750, minor_id = 10, fade_id = 1, align = 0 }); // Entry 1288
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 750, minor_id = 11, fade_id = 1, align = 0 }); // Entry 1289
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 750, minor_id = 101, fade_id = 1, align = 0 }); // Entry 1290
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 750, minor_id = 200, fade_id = 16, align = 0 }); // Entry 1291
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 750, minor_id = 210, fade_id = 16, align = 0 }); // Entry 1292
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 750, minor_id = 230, fade_id = 16, align = 0 }); // Entry 1293
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 750, minor_id = 240, fade_id = 16, align = 0 }); // Entry 1294
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 751, minor_id = 0, fade_id = 2, align = 0 }); // Entry 1295
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 751, minor_id = 3, fade_id = 8, align = 0 }); // Entry 1296
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 751, minor_id = 5, fade_id = 1, align = 0 }); // Entry 1297
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 751, minor_id = 10, fade_id = 2, align = 0 }); // Entry 1298
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 751, minor_id = 13, fade_id = 8, align = 0 }); // Entry 1299
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 751, minor_id = 15, fade_id = 1, align = 0 }); // Entry 1300
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 751, minor_id = 20, fade_id = 2, align = 0 }); // Entry 1301
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 751, minor_id = 23, fade_id = 8, align = 0 }); // Entry 1302
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 751, minor_id = 25, fade_id = 1, align = 0 }); // Entry 1303
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 751, minor_id = 30, fade_id = 2, align = 0 }); // Entry 1304
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 751, minor_id = 33, fade_id = 8, align = 0 }); // Entry 1305
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 751, minor_id = 35, fade_id = 1, align = 0 }); // Entry 1306
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 751, minor_id = 40, fade_id = 2, align = 0 }); // Entry 1307
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 751, minor_id = 43, fade_id = 8, align = 0 }); // Entry 1308
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 751, minor_id = 45, fade_id = 1, align = 0 }); // Entry 1309
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 751, minor_id = 50, fade_id = 2, align = 0 }); // Entry 1310
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 751, minor_id = 53, fade_id = 8, align = 0 }); // Entry 1311
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 751, minor_id = 55, fade_id = 1, align = 0 }); // Entry 1312
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 751, minor_id = 60, fade_id = 2, align = 0 }); // Entry 1313
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 751, minor_id = 63, fade_id = 8, align = 0 }); // Entry 1314
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 751, minor_id = 65, fade_id = 1, align = 0 }); // Entry 1315
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 751, minor_id = 70, fade_id = 2, align = 0 }); // Entry 1316
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 751, minor_id = 73, fade_id = 8, align = 0 }); // Entry 1317
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 751, minor_id = 75, fade_id = 1, align = 0 }); // Entry 1318
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 751, minor_id = 80, fade_id = 2, align = 0 }); // Entry 1319
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 751, minor_id = 83, fade_id = 8, align = 0 }); // Entry 1320
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 751, minor_id = 85, fade_id = 1, align = 0 }); // Entry 1321
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 751, minor_id = 95, fade_id = 1, align = 0 }); // Entry 1322
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 752, minor_id = 0, fade_id = 1, align = 0 }); // Entry 1323
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 752, minor_id = 10, fade_id = 1, align = 0 }); // Entry 1324
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 752, minor_id = 20, fade_id = 1, align = 0 }); // Entry 1325
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 752, minor_id = 30, fade_id = 1, align = 0 }); // Entry 1326
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 752, minor_id = 40, fade_id = 1, align = 0 }); // Entry 1327
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 752, minor_id = 50, fade_id = 1, align = 0 }); // Entry 1328
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 752, minor_id = 60, fade_id = 1, align = 0 }); // Entry 1329
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 752, minor_id = 70, fade_id = 1, align = 0 }); // Entry 1330
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 752, minor_id = 80, fade_id = 1, align = 0 }); // Entry 1331
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 752, minor_id = 90, fade_id = 1, align = 0 }); // Entry 1332
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 752, minor_id = 100, fade_id = 1, align = 0 }); // Entry 1333
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 752, minor_id = 110, fade_id = 1, align = 0 }); // Entry 1334
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 752, minor_id = 120, fade_id = 1, align = 0 }); // Entry 1335
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 753, minor_id = 0, fade_id = 16, align = 0 }); // Entry 1336
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 753, minor_id = 10, fade_id = 16, align = 0 }); // Entry 1337
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 753, minor_id = 20, fade_id = 16, align = 0 }); // Entry 1338
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 753, minor_id = 30, fade_id = 16, align = 0 }); // Entry 1339
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 753, minor_id = 40, fade_id = 16, align = 0 }); // Entry 1340
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 753, minor_id = 50, fade_id = 16, align = 0 }); // Entry 1341
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 753, minor_id = 60, fade_id = 16, align = 0 }); // Entry 1342
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 753, minor_id = 90, fade_id = 16, align = 0 }); // Entry 1343
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 753, minor_id = 70, fade_id = 16, align = 0 }); // Entry 1344
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 753, minor_id = 80, fade_id = 16, align = 0 }); // Entry 1345
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 754, minor_id = 0, fade_id = 16, align = 0 }); // Entry 1346
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 754, minor_id = 3, fade_id = 1, align = 0 }); // Entry 1347
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 754, minor_id = 10, fade_id = 16, align = 0 }); // Entry 1348
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 754, minor_id = 13, fade_id = 1, align = 0 }); // Entry 1349
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 754, minor_id = 20, fade_id = 16, align = 0 }); // Entry 1350
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 754, minor_id = 23, fade_id = 1, align = 0 }); // Entry 1351
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 754, minor_id = 30, fade_id = 16, align = 0 }); // Entry 1352
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 754, minor_id = 33, fade_id = 1, align = 0 }); // Entry 1353
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 754, minor_id = 40, fade_id = 16, align = 0 }); // Entry 1354
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 754, minor_id = 43, fade_id = 1, align = 0 }); // Entry 1355
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 754, minor_id = 50, fade_id = 16, align = 0 }); // Entry 1356
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 754, minor_id = 53, fade_id = 1, align = 0 }); // Entry 1357
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 754, minor_id = 60, fade_id = 16, align = 0 }); // Entry 1358
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 754, minor_id = 63, fade_id = 1, align = 0 }); // Entry 1359
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 754, minor_id = 70, fade_id = 16, align = 0 }); // Entry 1360
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 754, minor_id = 73, fade_id = 1, align = 0 }); // Entry 1361
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 754, minor_id = 80, fade_id = 16, align = 0 }); // Entry 1362
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 754, minor_id = 83, fade_id = 1, align = 0 }); // Entry 1363
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 754, minor_id = 90, fade_id = 16, align = 0 }); // Entry 1364
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 754, minor_id = 93, fade_id = 1, align = 0 }); // Entry 1365
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 754, minor_id = 200, fade_id = 16, align = 0 }); // Entry 1366
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 754, minor_id = 210, fade_id = 16, align = 0 }); // Entry 1367
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 754, minor_id = 500, fade_id = 1, align = 0 }); // Entry 1368
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 754, minor_id = 510, fade_id = 1, align = 0 }); // Entry 1369
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 760, minor_id = 1, fade_id = 1, align = 0 }); // Entry 1370
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 760, minor_id = 101, fade_id = 1, align = 0 }); // Entry 1371
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 760, minor_id = 201, fade_id = 1, align = 0 }); // Entry 1372
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 760, minor_id = 301, fade_id = 1, align = 0 }); // Entry 1373
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 760, minor_id = 321, fade_id = 1, align = 0 }); // Entry 1374
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 760, minor_id = 401, fade_id = 1, align = 0 }); // Entry 1375
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 760, minor_id = 501, fade_id = 1, align = 0 }); // Entry 1376
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 760, minor_id = 511, fade_id = 1, align = 0 }); // Entry 1377
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 760, minor_id = 611, fade_id = 1, align = 0 }); // Entry 1378
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 760, minor_id = 701, fade_id = 1, align = 0 }); // Entry 1379
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 760, minor_id = 721, fade_id = 1, align = 0 }); // Entry 1380
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 760, minor_id = 731, fade_id = 1, align = 0 }); // Entry 1381
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 760, minor_id = 741, fade_id = 1, align = 0 }); // Entry 1382
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 760, minor_id = 761, fade_id = 1, align = 0 }); // Entry 1383
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 760, minor_id = 771, fade_id = 1, align = 0 }); // Entry 1384
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 760, minor_id = 781, fade_id = 1, align = 0 }); // Entry 1385
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 760, minor_id = 791, fade_id = 1, align = 0 }); // Entry 1386
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 760, minor_id = 901, fade_id = 1, align = 0 }); // Entry 1387
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 760, minor_id = 910, fade_id = 1, align = 0 }); // Entry 1388
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 760, minor_id = 920, fade_id = 16, align = 0 }); // Entry 1389
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 761, minor_id = 1, fade_id = 2, align = 0 }); // Entry 1390
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 761, minor_id = 3, fade_id = 2, align = 0 }); // Entry 1391
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 761, minor_id = 5, fade_id = 2, align = 0 }); // Entry 1392
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 761, minor_id = 11, fade_id = 2, align = 0 }); // Entry 1393
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 761, minor_id = 13, fade_id = 2, align = 0 }); // Entry 1394
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 761, minor_id = 15, fade_id = 2, align = 0 }); // Entry 1395
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 761, minor_id = 101, fade_id = 1, align = 0 }); // Entry 1396
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 761, minor_id = 111, fade_id = 1, align = 0 }); // Entry 1397
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 761, minor_id = 301, fade_id = 2, align = 0 }); // Entry 1398
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 762, minor_id = 1, fade_id = 8, align = 0 }); // Entry 1399
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 762, minor_id = 101, fade_id = 8, align = 0 }); // Entry 1400
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 762, minor_id = 201, fade_id = 8, align = 0 }); // Entry 1401
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 762, minor_id = 301, fade_id = 8, align = 0 }); // Entry 1402
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 762, minor_id = 302, fade_id = 8, align = 0 }); // Entry 1403
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 762, minor_id = 303, fade_id = 8, align = 0 }); // Entry 1404
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 762, minor_id = 304, fade_id = 8, align = 0 }); // Entry 1405
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 762, minor_id = 305, fade_id = 8, align = 0 }); // Entry 1406
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 762, minor_id = 306, fade_id = 8, align = 0 }); // Entry 1407
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 762, minor_id = 311, fade_id = 8, align = 0 }); // Entry 1408
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 762, minor_id = 312, fade_id = 8, align = 0 }); // Entry 1409
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 762, minor_id = 313, fade_id = 8, align = 0 }); // Entry 1410
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 762, minor_id = 314, fade_id = 8, align = 0 }); // Entry 1411
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 762, minor_id = 315, fade_id = 8, align = 0 }); // Entry 1412
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 762, minor_id = 316, fade_id = 8, align = 0 }); // Entry 1413
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 762, minor_id = 501, fade_id = 8, align = 0 }); // Entry 1414
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 762, minor_id = 600, fade_id = 8, align = 0 }); // Entry 1415
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 762, minor_id = 701, fade_id = 8, align = 0 }); // Entry 1416
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 763, minor_id = 1, fade_id = 8, align = 0 }); // Entry 1417
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 763, minor_id = 11, fade_id = 8, align = 0 }); // Entry 1418
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 764, minor_id = 1, fade_id = 1, align = 0 }); // Entry 1419
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 764, minor_id = 101, fade_id = 8, align = 0 }); // Entry 1420
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 764, minor_id = 102, fade_id = 8, align = 0 }); // Entry 1421
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 764, minor_id = 103, fade_id = 8, align = 0 }); // Entry 1422
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 764, minor_id = 104, fade_id = 8, align = 0 }); // Entry 1423
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 764, minor_id = 111, fade_id = 8, align = 0 }); // Entry 1424
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 764, minor_id = 112, fade_id = 8, align = 0 }); // Entry 1425
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 764, minor_id = 113, fade_id = 8, align = 0 }); // Entry 1426
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 764, minor_id = 114, fade_id = 8, align = 0 }); // Entry 1427
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 765, minor_id = 1, fade_id = 8, align = 0 }); // Entry 1428
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 766, minor_id = 1, fade_id = 8, align = 0 }); // Entry 1429
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 766, minor_id = 2, fade_id = 8, align = 0 }); // Entry 1430
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 766, minor_id = 3, fade_id = 8, align = 0 }); // Entry 1431
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 767, minor_id = 201, fade_id = 1, align = 0 }); // Entry 1432
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 767, minor_id = 301, fade_id = 8, align = 0 }); // Entry 1433
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 770, minor_id = 7, fade_id = 16, align = 0 }); // Entry 1434
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 780, minor_id = 3, fade_id = 16, align = 0 }); // Entry 1435
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 780, minor_id = 5, fade_id = 16, align = 0 }); // Entry 1436
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 780, minor_id = 6, fade_id = 1, align = 0 }); // Entry 1437
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 780, minor_id = 101, fade_id = 16, align = 0 }); // Entry 1438
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 790, minor_id = 1, fade_id = 16, align = 0 }); // Entry 1439
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 790, minor_id = 11, fade_id = 1, align = 0 }); // Entry 1440
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 790, minor_id = 101, fade_id = 16, align = 0 }); // Entry 1441
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 790, minor_id = 201, fade_id = 16, align = 0 }); // Entry 1442
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 790, minor_id = 301, fade_id = 16, align = 0 }); // Entry 1443
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 791, minor_id = 1, fade_id = 18, align = 0 }); // Entry 1444
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 791, minor_id = 2, fade_id = 16, align = 0 }); // Entry 1445
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 791, minor_id = 3, fade_id = 16, align = 0 }); // Entry 1446
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 791, minor_id = 4, fade_id = 16, align = 0 }); // Entry 1447
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 791, minor_id = 5, fade_id = 16, align = 0 }); // Entry 1448
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 791, minor_id = 10, fade_id = 16, align = 0 }); // Entry 1449
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 791, minor_id = 11, fade_id = 16, align = 0 }); // Entry 1450
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 791, minor_id = 20, fade_id = 16, align = 0 }); // Entry 1451
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 791, minor_id = 30, fade_id = 16, align = 0 }); // Entry 1452
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 794, minor_id = 50, fade_id = 8, align = 0 }); // Entry 1453
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 795, minor_id = 0, fade_id = 16, align = 0 }); // Entry 1454
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 795, minor_id = 1, fade_id = 16, align = 0 }); // Entry 1455
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 795, minor_id = 2, fade_id = 16, align = 0 }); // Entry 1456
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 799, minor_id = 11, fade_id = 22, align = 0 }); // Entry 1457
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 799, minor_id = 2, fade_id = 16, align = 0 }); // Entry 1458
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 799, minor_id = 12, fade_id = 16, align = 0 }); // Entry 1459
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 800, minor_id = 21, fade_id = 8, align = 0 }); // Entry 1460
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 800, minor_id = 22, fade_id = 8, align = 0 }); // Entry 1461
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 800, minor_id = 31, fade_id = 8, align = 0 }); // Entry 1462
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 800, minor_id = 32, fade_id = 8, align = 0 }); // Entry 1463
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 800, minor_id = 41, fade_id = 8, align = 0 }); // Entry 1464
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 800, minor_id = 42, fade_id = 8, align = 0 }); // Entry 1465
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 800, minor_id = 71, fade_id = 8, align = 0 }); // Entry 1466
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 800, minor_id = 72, fade_id = 8, align = 0 }); // Entry 1467
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 803, minor_id = 41, fade_id = 8, align = 0 }); // Entry 1468
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 803, minor_id = 42, fade_id = 8, align = 0 }); // Entry 1469
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 803, minor_id = 63, fade_id = 8, align = 0 }); // Entry 1470
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 803, minor_id = 103, fade_id = 1, align = 0 }); // Entry 1471
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 803, minor_id = 173, fade_id = 1, align = 0 }); // Entry 1472
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 805, minor_id = 21, fade_id = 8, align = 0 }); // Entry 1473
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 805, minor_id = 22, fade_id = 8, align = 0 }); // Entry 1474
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 805, minor_id = 31, fade_id = 8, align = 0 }); // Entry 1475
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 805, minor_id = 32, fade_id = 8, align = 0 }); // Entry 1476
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 805, minor_id = 61, fade_id = 8, align = 0 }); // Entry 1477
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 805, minor_id = 62, fade_id = 8, align = 0 }); // Entry 1478
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 805, minor_id = 91, fade_id = 8, align = 0 }); // Entry 1479
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 805, minor_id = 92, fade_id = 8, align = 0 }); // Entry 1480
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 806, minor_id = 31, fade_id = 8, align = 0 }); // Entry 1481
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 806, minor_id = 32, fade_id = 8, align = 0 }); // Entry 1482
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 806, minor_id = 41, fade_id = 8, align = 0 }); // Entry 1483
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 806, minor_id = 42, fade_id = 8, align = 0 }); // Entry 1484
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 806, minor_id = 91, fade_id = 8, align = 0 }); // Entry 1485
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 806, minor_id = 92, fade_id = 8, align = 0 }); // Entry 1486
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 806, minor_id = 221, fade_id = 8, align = 0 }); // Entry 1487
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 806, minor_id = 222, fade_id = 8, align = 0 }); // Entry 1488
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 807, minor_id = 21, fade_id = 8, align = 0 }); // Entry 1489
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 807, minor_id = 22, fade_id = 8, align = 0 }); // Entry 1490
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 807, minor_id = 71, fade_id = 8, align = 0 }); // Entry 1491
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 807, minor_id = 72, fade_id = 8, align = 0 }); // Entry 1492
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 810, minor_id = 31, fade_id = 8, align = 0 }); // Entry 1493
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 810, minor_id = 32, fade_id = 8, align = 0 }); // Entry 1494
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 810, minor_id = 33, fade_id = 8, align = 0 }); // Entry 1495
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 810, minor_id = 123, fade_id = 1, align = 0 }); // Entry 1496
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 810, minor_id = 153, fade_id = 1, align = 0 }); // Entry 1497
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 811, minor_id = 91, fade_id = 8, align = 0 }); // Entry 1498
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 811, minor_id = 92, fade_id = 8, align = 0 }); // Entry 1499
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 811, minor_id = 103, fade_id = 1, align = 0 }); // Entry 1500
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 811, minor_id = 133, fade_id = 1, align = 0 }); // Entry 1501
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 811, minor_id = 221, fade_id = 8, align = 0 }); // Entry 1502
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 811, minor_id = 222, fade_id = 8, align = 0 }); // Entry 1503
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 812, minor_id = 21, fade_id = 8, align = 0 }); // Entry 1504
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 812, minor_id = 22, fade_id = 8, align = 0 }); // Entry 1505
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 812, minor_id = 23, fade_id = 8, align = 0 }); // Entry 1506
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 812, minor_id = 31, fade_id = 8, align = 0 }); // Entry 1507
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 812, minor_id = 32, fade_id = 8, align = 0 }); // Entry 1508
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 812, minor_id = 71, fade_id = 8, align = 0 }); // Entry 1509
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 812, minor_id = 72, fade_id = 8, align = 0 }); // Entry 1510
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 812, minor_id = 133, fade_id = 8, align = 0 }); // Entry 1511
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 812, minor_id = 143, fade_id = 1, align = 0 }); // Entry 1512
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 812, minor_id = 153, fade_id = 1, align = 0 }); // Entry 1513
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 812, minor_id = 31, fade_id = 8, align = 0 }); // Entry 1514
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 812, minor_id = 32, fade_id = 8, align = 0 }); // Entry 1515
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 814, minor_id = 31, fade_id = 8, align = 0 }); // Entry 1516
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 814, minor_id = 32, fade_id = 8, align = 0 }); // Entry 1517
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 814, minor_id = 71, fade_id = 8, align = 0 }); // Entry 1518
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 814, minor_id = 72, fade_id = 8, align = 0 }); // Entry 1519
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 814, minor_id = 91, fade_id = 8, align = 0 }); // Entry 1520
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 814, minor_id = 92, fade_id = 8, align = 0 }); // Entry 1521
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 814, minor_id = 93, fade_id = 8, align = 0 }); // Entry 1522
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 815, minor_id = 61, fade_id = 8, align = 0 }); // Entry 1523
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 815, minor_id = 62, fade_id = 8, align = 0 }); // Entry 1524
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 815, minor_id = 71, fade_id = 8, align = 0 }); // Entry 1525
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 815, minor_id = 72, fade_id = 8, align = 0 }); // Entry 1526
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 815, minor_id = 91, fade_id = 8, align = 0 }); // Entry 1527
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 815, minor_id = 92, fade_id = 8, align = 0 }); // Entry 1528
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 815, minor_id = 123, fade_id = 1, align = 0 }); // Entry 1529
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 815, minor_id = 133, fade_id = 8, align = 0 }); // Entry 1530
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 815, minor_id = 173, fade_id = 1, align = 0 }); // Entry 1531
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 815, minor_id = 221, fade_id = 8, align = 0 }); // Entry 1532
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 815, minor_id = 222, fade_id = 8, align = 0 }); // Entry 1533
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 816, minor_id = 21, fade_id = 8, align = 0 }); // Entry 1534
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 816, minor_id = 22, fade_id = 8, align = 0 }); // Entry 1535
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 816, minor_id = 31, fade_id = 8, align = 0 }); // Entry 1536
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 816, minor_id = 32, fade_id = 8, align = 0 }); // Entry 1537
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 817, minor_id = 91, fade_id = 8, align = 0 }); // Entry 1538
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 817, minor_id = 92, fade_id = 8, align = 0 }); // Entry 1539
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 817, minor_id = 163, fade_id = 8, align = 0 }); // Entry 1540
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 818, minor_id = 41, fade_id = 8, align = 0 }); // Entry 1541
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 818, minor_id = 42, fade_id = 8, align = 0 }); // Entry 1542
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 818, minor_id = 61, fade_id = 8, align = 0 }); // Entry 1543
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 818, minor_id = 62, fade_id = 8, align = 0 }); // Entry 1544
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 818, minor_id = 91, fade_id = 8, align = 0 }); // Entry 1545
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 818, minor_id = 92, fade_id = 8, align = 0 }); // Entry 1546
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 818, minor_id = 123, fade_id = 1, align = 0 }); // Entry 1547
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 821, minor_id = 41, fade_id = 8, align = 0 }); // Entry 1548
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 821, minor_id = 42, fade_id = 8, align = 0 }); // Entry 1549
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 821, minor_id = 43, fade_id = 8, align = 0 }); // Entry 1550
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 821, minor_id = 61, fade_id = 8, align = 0 }); // Entry 1551
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 821, minor_id = 62, fade_id = 8, align = 0 }); // Entry 1552
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 821, minor_id = 143, fade_id = 1, align = 0 }); // Entry 1553
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 822, minor_id = 21, fade_id = 8, align = 0 }); // Entry 1554
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 822, minor_id = 22, fade_id = 8, align = 0 }); // Entry 1555
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 822, minor_id = 31, fade_id = 8, align = 0 }); // Entry 1556
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 822, minor_id = 32, fade_id = 8, align = 0 }); // Entry 1557
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 822, minor_id = 41, fade_id = 8, align = 0 }); // Entry 1558
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 822, minor_id = 42, fade_id = 8, align = 0 }); // Entry 1559
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 822, minor_id = 61, fade_id = 8, align = 0 }); // Entry 1560
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 822, minor_id = 62, fade_id = 8, align = 0 }); // Entry 1561
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 822, minor_id = 71, fade_id = 8, align = 0 }); // Entry 1562
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 822, minor_id = 72, fade_id = 8, align = 0 }); // Entry 1563
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 822, minor_id = 91, fade_id = 8, align = 0 }); // Entry 1564
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 822, minor_id = 92, fade_id = 8, align = 0 }); // Entry 1565
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 822, minor_id = 163, fade_id = 8, align = 0 }); // Entry 1566
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 822, minor_id = 173, fade_id = 1, align = 0 }); // Entry 1567
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 822, minor_id = 221, fade_id = 8, align = 0 }); // Entry 1568
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 822, minor_id = 222, fade_id = 8, align = 0 }); // Entry 1569
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 824, minor_id = 21, fade_id = 8, align = 0 }); // Entry 1570
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 824, minor_id = 22, fade_id = 8, align = 0 }); // Entry 1571
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 824, minor_id = 31, fade_id = 8, align = 0 }); // Entry 1572
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 824, minor_id = 32, fade_id = 8, align = 0 }); // Entry 1573
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 824, minor_id = 41, fade_id = 8, align = 0 }); // Entry 1574
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 824, minor_id = 42, fade_id = 8, align = 0 }); // Entry 1575
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 824, minor_id = 61, fade_id = 8, align = 0 }); // Entry 1576
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 824, minor_id = 62, fade_id = 8, align = 0 }); // Entry 1577
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 824, minor_id = 71, fade_id = 8, align = 0 }); // Entry 1578
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 824, minor_id = 72, fade_id = 8, align = 0 }); // Entry 1579
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 824, minor_id = 91, fade_id = 8, align = 0 }); // Entry 1580
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 824, minor_id = 92, fade_id = 8, align = 0 }); // Entry 1581
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 824, minor_id = 221, fade_id = 8, align = 0 }); // Entry 1582
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 824, minor_id = 222, fade_id = 8, align = 0 }); // Entry 1583
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 825, minor_id = 21, fade_id = 8, align = 0 }); // Entry 1584
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 825, minor_id = 22, fade_id = 8, align = 0 }); // Entry 1585
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 825, minor_id = 71, fade_id = 8, align = 0 }); // Entry 1586
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 825, minor_id = 72, fade_id = 8, align = 0 }); // Entry 1587
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 825, minor_id = 103, fade_id = 1, align = 0 }); // Entry 1588
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 825, minor_id = 153, fade_id = 1, align = 0 }); // Entry 1589
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 826, minor_id = 21, fade_id = 8, align = 0 }); // Entry 1590
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 826, minor_id = 22, fade_id = 8, align = 0 }); // Entry 1591
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 826, minor_id = 31, fade_id = 8, align = 0 }); // Entry 1592
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 826, minor_id = 32, fade_id = 8, align = 0 }); // Entry 1593
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 826, minor_id = 61, fade_id = 8, align = 0 }); // Entry 1594
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 826, minor_id = 62, fade_id = 8, align = 0 }); // Entry 1595
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 826, minor_id = 91, fade_id = 8, align = 0 }); // Entry 1596
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 826, minor_id = 92, fade_id = 8, align = 0 }); // Entry 1597
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 826, minor_id = 221, fade_id = 8, align = 0 }); // Entry 1598
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 826, minor_id = 222, fade_id = 8, align = 0 }); // Entry 1599
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 826, minor_id = 103, fade_id = 1, align = 0 }); // Entry 1600
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 826, minor_id = 133, fade_id = 1, align = 0 }); // Entry 1601
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 826, minor_id = 143, fade_id = 1, align = 0 }); // Entry 1602
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 826, minor_id = 153, fade_id = 1, align = 0 }); // Entry 1603
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 826, minor_id = 173, fade_id = 1, align = 0 }); // Entry 1604
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 827, minor_id = 61, fade_id = 8, align = 0 }); // Entry 1605
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 827, minor_id = 62, fade_id = 8, align = 0 }); // Entry 1606
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 827, minor_id = 123, fade_id = 1, align = 0 }); // Entry 1607
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 827, minor_id = 143, fade_id = 1, align = 0 }); // Entry 1608
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 827, minor_id = 173, fade_id = 1, align = 0 }); // Entry 1609
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 828, minor_id = 21, fade_id = 16, align = 0 }); // Entry 1610
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 828, minor_id = 22, fade_id = 16, align = 0 }); // Entry 1611
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 828, minor_id = 31, fade_id = 16, align = 0 }); // Entry 1612
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 828, minor_id = 32, fade_id = 16, align = 0 }); // Entry 1613
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 828, minor_id = 61, fade_id = 16, align = 0 }); // Entry 1614
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 828, minor_id = 62, fade_id = 16, align = 0 }); // Entry 1615
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 828, minor_id = 91, fade_id = 16, align = 0 }); // Entry 1616
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 828, minor_id = 92, fade_id = 16, align = 0 }); // Entry 1617
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 828, minor_id = 101, fade_id = 1, align = 0 }); // Entry 1618
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 828, minor_id = 102, fade_id = 1, align = 0 }); // Entry 1619
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 828, minor_id = 103, fade_id = 16, align = 0 }); // Entry 1620
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 828, minor_id = 131, fade_id = 1, align = 0 }); // Entry 1621
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 828, minor_id = 132, fade_id = 1, align = 0 }); // Entry 1622
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 828, minor_id = 133, fade_id = 16, align = 0 }); // Entry 1623
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 828, minor_id = 141, fade_id = 1, align = 0 }); // Entry 1624
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 828, minor_id = 142, fade_id = 1, align = 0 }); // Entry 1625
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 828, minor_id = 143, fade_id = 16, align = 0 }); // Entry 1626
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 828, minor_id = 151, fade_id = 1, align = 0 }); // Entry 1627
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 828, minor_id = 152, fade_id = 1, align = 0 }); // Entry 1628
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 828, minor_id = 153, fade_id = 16, align = 0 }); // Entry 1629
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 828, minor_id = 171, fade_id = 1, align = 0 }); // Entry 1630
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 828, minor_id = 172, fade_id = 1, align = 0 }); // Entry 1631
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 828, minor_id = 173, fade_id = 16, align = 0 }); // Entry 1632
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 828, minor_id = 221, fade_id = 16, align = 0 }); // Entry 1633
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 828, minor_id = 222, fade_id = 16, align = 0 }); // Entry 1634
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 829, minor_id = 41, fade_id = 8, align = 0 }); // Entry 1635
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 829, minor_id = 42, fade_id = 8, align = 0 }); // Entry 1636
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 829, minor_id = 221, fade_id = 8, align = 0 }); // Entry 1637
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 829, minor_id = 222, fade_id = 8, align = 0 }); // Entry 1638
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 829, minor_id = 163, fade_id = 8, align = 0 }); // Entry 1639
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 830, minor_id = 71, fade_id = 8, align = 0 }); // Entry 1640
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 830, minor_id = 72, fade_id = 8, align = 0 }); // Entry 1641
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 830, minor_id = 91, fade_id = 8, align = 0 }); // Entry 1642
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 830, minor_id = 92, fade_id = 8, align = 0 }); // Entry 1643
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 840, minor_id = 21, fade_id = 8, align = 0 }); // Entry 1644
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 840, minor_id = 31, fade_id = 8, align = 0 }); // Entry 1645
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 840, minor_id = 41, fade_id = 8, align = 0 }); // Entry 1646
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 840, minor_id = 51, fade_id = 1, align = 0 }); // Entry 1647
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 840, minor_id = 61, fade_id = 8, align = 0 }); // Entry 1648
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 840, minor_id = 71, fade_id = 8, align = 0 }); // Entry 1649
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 840, minor_id = 72, fade_id = 8, align = 0 }); // Entry 1650
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 840, minor_id = 91, fade_id = 16, align = 0 }); // Entry 1651
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 840, minor_id = 92, fade_id = 8, align = 0 }); // Entry 1652
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 840, minor_id = 101, fade_id = 1, align = 0 }); // Entry 1653
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 840, minor_id = 121, fade_id = 1, align = 0 }); // Entry 1654
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 840, minor_id = 131, fade_id = 2, align = 0 }); // Entry 1655
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 840, minor_id = 141, fade_id = 1, align = 0 }); // Entry 1656
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 840, minor_id = 151, fade_id = 1, align = 0 }); // Entry 1657
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 840, minor_id = 161, fade_id = 8, align = 0 }); // Entry 1658
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 840, minor_id = 171, fade_id = 1, align = 0 }); // Entry 1659
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 840, minor_id = 191, fade_id = 1, align = 0 }); // Entry 1660
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 840, minor_id = 221, fade_id = 8, align = 0 }); // Entry 1661
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 840, minor_id = 231, fade_id = 8, align = 0 }); // Entry 1662
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 840, minor_id = 261, fade_id = 1, align = 0 }); // Entry 1663
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 880, minor_id = 1, fade_id = 16, align = 0 }); // Entry 1664
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 880, minor_id = 2, fade_id = 16, align = 0 }); // Entry 1665
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 880, minor_id = 3, fade_id = 16, align = 0 }); // Entry 1666
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 880, minor_id = 4, fade_id = 16, align = 0 }); // Entry 1667
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 880, minor_id = 5, fade_id = 16, align = 0 }); // Entry 1668
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 880, minor_id = 6, fade_id = 16, align = 0 }); // Entry 1669
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 880, minor_id = 7, fade_id = 16, align = 0 }); // Entry 1670
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 880, minor_id = 8, fade_id = 16, align = 0 }); // Entry 1671
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 880, minor_id = 9, fade_id = 16, align = 0 }); // Entry 1672
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 880, minor_id = 10, fade_id = 16, align = 0 }); // Entry 1673
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 880, minor_id = 101, fade_id = 16, align = 0 }); // Entry 1674
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 880, minor_id = 102, fade_id = 16, align = 0 }); // Entry 1675
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 880, minor_id = 103, fade_id = 16, align = 0 }); // Entry 1676
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 881, minor_id = 101, fade_id = 16, align = 0 }); // Entry 1677
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 881, minor_id = 102, fade_id = 16, align = 0 }); // Entry 1678
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 881, minor_id = 103, fade_id = 16, align = 0 }); // Entry 1679
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 881, minor_id = 201, fade_id = 16, align = 0 }); // Entry 1680
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 881, minor_id = 202, fade_id = 1, align = 0 }); // Entry 1681
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 881, minor_id = 203, fade_id = 1, align = 0 }); // Entry 1682
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 881, minor_id = 301, fade_id = 1, align = 0 }); // Entry 1683
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 991, minor_id = 1, fade_id = 1, align = 0 }); // Entry 1684
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 991, minor_id = 2, fade_id = 1, align = 0 }); // Entry 1685
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 991, minor_id = 3, fade_id = 1, align = 0 }); // Entry 1686
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 992, minor_id = 1, fade_id = 21, align = 0 }); // Entry 1687
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 992, minor_id = 2, fade_id = 16, align = 0 }); // Entry 1688
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 992, minor_id = 3, fade_id = 16, align = 0 }); // Entry 1689
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 992, minor_id = 4, fade_id = 16, align = 0 }); // Entry 1690
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 993, minor_id = 1, fade_id = 16, align = 0 }); // Entry 1691
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 993, minor_id = 2, fade_id = 1, align = 0 }); // Entry 1692
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 994, minor_id = 1, fade_id = 16, align = 0 }); // Entry 1693
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 995, minor_id = 1, fade_id = 16, align = 0 }); // Entry 1694
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 996, minor_id = 1, fade_id = 1, align = 0 }); // Entry 1695
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 996, minor_id = 2, fade_id = 1, align = 0 }); // Entry 1696
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 997, minor_id = 1, fade_id = 16, align = 0 }); // Entry 1697
            EvtFadeoutTable.Add(new EvtFadeoutEntry { major_id = 998, minor_id = 1, fade_id = 1, align = 0 }); // Entry 1698
        }

        #region Standard Overrides
        public override void ConfigurationUpdated(Config configuration)
        {
            // Apply settings from configuration.
            // ... your code here.
            _configuration = configuration;
            _logger.WriteLine($"[{_modConfig.ModId}] Config Updated: Applying");
        }
        #endregion

        #region For Exports, Serialization etc.
#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
        public Mod() { }
#pragma warning restore CS8618
        #endregion
    }
}