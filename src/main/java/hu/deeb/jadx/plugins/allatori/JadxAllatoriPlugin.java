package hu.deeb.jadx.plugins.allatori;

import jadx.api.plugins.JadxPlugin;
import jadx.api.plugins.JadxPluginContext;
import jadx.api.plugins.JadxPluginInfo;
import jadx.api.plugins.JadxPluginInfoBuilder;

public class JadxAllatoriPlugin implements JadxPlugin {
	public static final String PLUGIN_ID = "example-plugin";

	@Override
	public JadxPluginInfo getPluginInfo() {
		return JadxPluginInfoBuilder.pluginId(PLUGIN_ID)
				.name("Jadx Allatori deobfuscate plugin")
				.description("Replace known Allatori string decrypt calls with decoded string constants")
				.requiredJadxVersion("1.5.1, r2333")
				.build();
	}

	@Override
	public void init(JadxPluginContext context) {
		context.addPass(new AllatoriDeobfuscatePass());
	}
}
