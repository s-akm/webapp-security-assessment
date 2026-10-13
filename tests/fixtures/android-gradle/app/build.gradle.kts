// 架空の設定。動くビルドではない
android {
    namespace = "com.example.notes"
    buildTypes {
        getByName("debug") {
            isDebuggable = true
        }
        getByName("release") {
            isMinifyEnabled = true
            isDebuggable = false
            // isDebuggable = true
        }
    }
}

dependencies {
    implementation(libs.uikit)
    implementation(libs.netclient)
    testImplementation("com.example.test:runner:4.13.2")
}
