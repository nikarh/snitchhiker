# The Rust core calls nothing back; its native methods are looked up by name.
-keep class dev.nikarh.snitchhiker.app.Native { native <methods>; }
# Wire's adapters are found by reflection of the generated classes.
-keep class snitchhiker.v1.** { *; }
