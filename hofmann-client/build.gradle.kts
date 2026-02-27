
plugins {
    id("buildlogic.java-library-conventions")
    id("buildlogic.publish-conventions")
}

description = "Hofmann API client"

dependencies {
    api(project(":hofmann-rfc"))

    implementation(libs.javax.inject)
    implementation(libs.bundles.core)
    implementation(libs.bundles.jackson)

    testImplementation(libs.bundles.test)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}
