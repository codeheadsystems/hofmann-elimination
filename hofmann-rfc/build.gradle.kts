
plugins {
    id("buildlogic.java-library-conventions")
}

description = "Hofmann's RFC implementation for OPRF and OPAQUE"

dependencies {
    implementation(libs.javax.inject)
    implementation(libs.bundles.core)
    implementation(libs.bundles.jackson)

    testImplementation(libs.bundles.test)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}