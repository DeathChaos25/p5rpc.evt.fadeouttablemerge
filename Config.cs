using System.ComponentModel;
using p5rpc.evt.fadeouttablemerge.Template.Configuration;
using Reloaded.Mod.Interfaces.Structs;

namespace p5rpc.evt.fadeouttablemerge.Configuration
{
    public class Config : Configurable<Config>
    {
        [DisplayName("Debug")]
        [Description("Display extra messages for debugging purposes")]
        [DefaultValue(false)]
        public bool Debug { get; set; } = false;
    }

    /// <summary>
    /// Allows you to override certain aspects of the configuration creation process (e.g. create multiple configurations).
    /// Override elements in <see cref="ConfiguratorMixinBase"/> for finer control.
    /// </summary>
    public class ConfiguratorMixin : ConfiguratorMixinBase
    {
        // 
    }
}
