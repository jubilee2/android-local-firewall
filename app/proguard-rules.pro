# Project-specific ProGuard rules belong in this file.
-keep class com.localfirewall.app.network.outline.OutlineNativeBridge { *; }
-keep interface com.localfirewall.app.network.outline.NativeForwarderCallbacks { *; }
-keep class * implements com.localfirewall.app.network.outline.NativeForwarderCallbacks {
    public boolean admitPacket(int, int, byte[], int, byte[], int, int, int, boolean);
    public boolean protectSocket(int);
    public void onFatalError(java.lang.String);
}
